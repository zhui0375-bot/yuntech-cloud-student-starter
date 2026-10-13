#!/usr/bin/env python3
"""Forward allowlisted W6 MQTT events to the local inspection API."""

import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import paho.mqtt
    import paho.mqtt.client as mqtt
except ImportError:
    print("ERROR: paho-mqtt==2.1.0 is required", file=sys.stderr)
    raise SystemExit(2)


CODE = "group5-ww"
EXPECTED_DEVICES = {f"{CODE}-d{number:02d}" for number in range(1, 11)}
EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENDPOINT_PATTERN = re.compile(r"^[A-Za-z0-9-]+\.iot\.us-east-1\.amazonaws\.com$")
MAX_EVENT_BYTES = 4096
API_URL = "http://127.0.0.1:8080/events"


def reason_value(reason):
    return int(getattr(reason, "value", reason))


def required_env(name):
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def checked_file(name, private=False):
    path = Path(required_env(name))
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{name} must point to a regular file")
    if private and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError(f"{name} file must have mode 600")
    return path


def load_config():
    if paho.mqtt.__version__ != "2.1.0":
        raise ValueError("paho-mqtt==2.1.0 is required")
    endpoint = required_env("IOT_ENDPOINT")
    topic = required_env("IOT_TOPIC")
    client_id = required_env("IOT_CLIENT_ID")
    device_id_values = required_env("IOT_DEVICE_IDS").split(",")
    device_ids = set(device_id_values)
    reporter_token = required_env("REPORTER_TOKEN")
    if not ENDPOINT_PATTERN.fullmatch(endpoint):
        raise ValueError("IOT_ENDPOINT is not a valid us-east-1 IoT endpoint")
    if topic != f"cxe/{CODE}/gw/events":
        raise ValueError("IOT_TOPIC does not match the configured W6 topic")
    if client_id != f"consumer-{CODE}":
        raise ValueError("IOT_CLIENT_ID does not match the configured W6 consumer ID")
    if len(device_id_values) != len(EXPECTED_DEVICES) or device_ids != EXPECTED_DEVICES:
        raise ValueError("IOT_DEVICE_IDS must contain exactly the ten configured W6 devices")

    return {
        "endpoint": endpoint,
        "topic": topic,
        "client_id": client_id,
        "device_ids": device_ids,
        "reporter_token": reporter_token,
        "ca": checked_file("IOT_CA", private=True),
        "cert": checked_file("IOT_CERT", private=True),
        "key": checked_file("IOT_KEY", private=True),
    }


def safe_event_id(value):
    event_id = value.get("event_id") if isinstance(value, dict) else None
    return event_id if isinstance(event_id, str) and EVENT_ID_PATTERN.fullmatch(event_id) else "invalid"


def post_event(event, reporter_token):
    body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = Request(
        API_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {reporter_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
    except (URLError, TimeoutError, OSError):
        return "error"

    if status == 201:
        return "created"
    if status == 200:
        return "duplicate"
    if 400 <= status < 500:
        return "rejected"
    return "error"


class InspectionConsumer:
    def __init__(self, config):
        self.config = config
        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=config["client_id"],
            protocol=mqtt.MQTTv5,
            transport="tcp",
        )
        self.client.tls_set(
            ca_certs=str(config["ca"]),
            certfile=str(config["cert"]),
            keyfile=str(config["key"]),
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        self.client.on_connect = self.on_connect
        self.client.on_subscribe = self.on_subscribe
        self.client.on_message = self.on_message

    def on_connect(self, client, _userdata, _flags, reason_code, _properties):
        reason = reason_value(reason_code)
        if reason >= 128:
            print(f"MQTT connection rejected rc={reason}", file=sys.stderr, flush=True)
            return
        result, _message_id = client.subscribe(self.config["topic"], qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            print(f"MQTT subscribe request failed rc={result}", file=sys.stderr, flush=True)

    def on_subscribe(self, _client, _userdata, _message_id, reason_codes, _properties):
        codes = [reason_value(reason) for reason in reason_codes]
        reason = codes[0] if codes else 128
        if reason < 128:
            print(f"subscribed rc={reason}", flush=True)
        else:
            print(f"MQTT subscription rejected rc={reason}", file=sys.stderr, flush=True)

    def on_message(self, _client, _userdata, message):
        event_id = "invalid"
        result = "rejected"
        if len(message.payload) <= MAX_EVENT_BYTES:
            try:
                event = json.loads(message.payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                event = None
            event_id = safe_event_id(event)
            if isinstance(event, dict):
                device_id = event.get("device_id")
                if isinstance(device_id, str) and device_id in self.config["device_ids"]:
                    result = post_event(event, self.config["reporter_token"])
        print(f"event_id={event_id} result={result}", flush=True)

    def run(self):
        self.client.connect(self.config["endpoint"], 8883, keepalive=60)
        self.client.loop_forever()


def main():
    consumer = InspectionConsumer(load_config())
    consumer.run()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
