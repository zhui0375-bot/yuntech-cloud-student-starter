#!/usr/bin/env python3
"""Check the W6 AWS IoT MQTT 5 gateway and consumer identities."""

import argparse
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import threading
import time

try:
    import paho.mqtt
    import paho.mqtt.client as mqtt
except ImportError:
    print("ERROR: install paho-mqtt==2.1.0 in the active Python environment", file=sys.stderr)
    raise SystemExit(2)


ROOT = Path(__file__).resolve().parents[1]
CODE = "group5-ww"
RESOURCE_FILE = ROOT / ".local" / "resources.json"
IOT_DIR = ROOT / ".local" / "iot"
EXPECTED_VERSION = "2.1.0"


def safe_file(path, private=False):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Required IoT file is missing or unsafe: {path.name}")
    if private and (os.stat(path).st_mode & 0o077):
        raise ValueError(f"{path.name} permissions are too broad; use mode 600")
    return path


def load_settings(identity):
    if paho.mqtt.__version__ != EXPECTED_VERSION:
        raise ValueError(f"paho-mqtt {EXPECTED_VERSION} is required in the active Python environment")
    if ROOT.joinpath(".local").is_symlink() or IOT_DIR.is_symlink():
        raise ValueError("Refusing a symlink in the local IoT configuration path")
    if not IOT_DIR.is_dir() or stat.S_IMODE(IOT_DIR.stat().st_mode) != 0o700:
        raise ValueError(".local/iot must be a directory with mode 700")
    if RESOURCE_FILE.is_symlink() or not RESOURCE_FILE.is_file():
        raise ValueError("Missing or unsafe .local/resources.json")
    resources = json.loads(RESOURCE_FILE.read_text(encoding="utf-8"))
    if resources.get("group") != "group5" or resources.get("owner") != "ww":
        raise ValueError("resources.json does not identify group5-ww")

    is_gateway = identity == "gw"
    cert_name = "gw.cert.pem" if is_gateway else "consumer.cert.pem"
    key_name = "gw.private.key" if is_gateway else "consumer.private.key"
    cert_id_key = "iot_gw_cert_id" if is_gateway else "iot_consumer_cert_id"
    if not resources.get(cert_id_key):
        raise ValueError(f"resources.json is missing {cert_id_key}")

    endpoint_file = safe_file(IOT_DIR / "endpoint", private=True)
    endpoint = endpoint_file.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]+\.iot\.us-east-1\.amazonaws\.com", endpoint):
        raise ValueError("The saved IoT endpoint is not a valid us-east-1 endpoint")

    return {
        "endpoint": endpoint,
        "ca": safe_file(IOT_DIR / "AmazonRootCA1.pem", private=True),
        "cert": safe_file(IOT_DIR / cert_name, private=True),
        "key": safe_file(IOT_DIR / key_name, private=True),
        "client_id": f"{identity}-{CODE}",
    }


class MqttCheck:
    def __init__(self, settings, action, topic, wait_seconds):
        self.settings = settings
        self.action = action
        self.topic = topic
        self.wait_seconds = wait_seconds
        self.connected = threading.Event()
        self.subscribed = threading.Event()
        self.received = threading.Event()
        self.condition = threading.Condition()
        self.connection_reason = None
        self.subscription_reason = None
        self.subscription_mid = None
        self.publish_reasons = {}
        self.messages = []
        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=settings["client_id"],
            protocol=mqtt.MQTTv5,
            transport="tcp",
        )
        self.client.tls_set(
            ca_certs=str(settings["ca"]),
            certfile=str(settings["cert"]),
            keyfile=str(settings["key"]),
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        self.client.on_connect = self.on_connect
        self.client.on_subscribe = self.on_subscribe
        self.client.on_publish = self.on_publish
        self.client.on_message = self.on_message

    @staticmethod
    def reason_value(reason):
        return int(getattr(reason, "value", reason))

    def on_connect(self, _client, _userdata, _flags, reason_code, _properties):
        self.connection_reason = self.reason_value(reason_code)
        print(f"connack={self.connection_reason}", flush=True)
        self.connected.set()

    def on_subscribe(self, _client, _userdata, mid, reason_codes, _properties):
        if self.subscription_mid is not None and mid != self.subscription_mid:
            return
        self.subscription_mid = mid
        values = [self.reason_value(reason) for reason in reason_codes]
        self.subscription_reason = values[0] if values else 128
        print(f"suback={self.subscription_reason}", flush=True)
        self.subscribed.set()

    def on_publish(self, _client, _userdata, mid, reason_code, _properties):
        with self.condition:
            self.publish_reasons[mid] = self.reason_value(reason_code)
            self.condition.notify_all()

    def on_message(self, _client, _userdata, message):
        payload = message.payload.decode("utf-8", errors="replace")
        self.messages.append((message.topic, payload))
        print(f"recv topic={message.topic} payload={payload}", flush=True)
        self.received.set()

    def run(self):
        try:
            self.client.connect_async(self.settings["endpoint"], 8883, keepalive=60)
            self.client.loop_start()
            if not self.connected.wait(15):
                raise TimeoutError("Timed out waiting for MQTT CONNACK")
            if self.connection_reason >= 128:
                return 1
            if self.action == "pub":
                return self.publish()
            return self.subscribe()
        finally:
            try:
                self.client.disconnect()
            finally:
                self.client.loop_stop()

    def publish(self):
        payload = json.dumps({"check": "t2", "code": CODE}, separators=(",", ":"))
        info = self.client.publish(self.topic, payload=payload, qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed with local status {info.rc}")
        deadline = time.monotonic() + 15
        with self.condition:
            while info.mid not in self.publish_reasons:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for PUBACK")
                self.condition.wait(remaining)
            reason = self.publish_reasons[info.mid]
        print(f"puback={reason}", flush=True)
        return 0 if reason < 128 else 1

    def subscribe(self):
        result, mid = self.client.subscribe(self.topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscribe failed with local status {result}")
        self.subscription_mid = mid
        if not self.subscribed.wait(15):
            raise TimeoutError("Timed out waiting for SUBACK")
        if self.subscription_reason >= 128:
            return 1
        if not self.received.wait(self.wait_seconds):
            raise TimeoutError("Timed out waiting for a message")
        return 0


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="identity", required=True, choices=("gw", "consumer"))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--pub", metavar="TOPIC")
    action.add_argument("--sub", metavar="TOPIC_FILTER")
    parser.add_argument("--wait", type=int, default=60, metavar="SECONDS")
    args = parser.parse_args()
    if args.wait < 1 or args.wait > 3600:
        parser.error("--wait must be between 1 and 3600 seconds")
    if args.pub is not None and args.wait != 60:
        parser.error("--wait is only valid with --sub")
    return args


def main():
    args = parse_args()
    action = "pub" if args.pub is not None else "sub"
    topic = args.pub if action == "pub" else args.sub
    if not topic or "\x00" in topic:
        raise ValueError("A non-empty MQTT topic is required")
    settings = load_settings(args.identity)
    return MqttCheck(settings, action, topic, args.wait).run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
