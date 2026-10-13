#!/usr/bin/env python3
"""Publish the W6 32-event device simulation and wait for every PUBACK."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import mqtt_check


CODE = "group5-ww"
RUN_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,40}$")
LAST_RUN_FILE = ROOT / ".local" / "w06-last-run.json"
DEVICE_IDS = tuple(f"{CODE}-d{number:02d}" for number in range(1, 11))


def build_events(code, run):
    if not RUN_PATTERN.fullmatch(code) or code != CODE:
        raise ValueError("code must be the configured W6 device code")
    if not RUN_PATTERN.fullmatch(run):
        raise ValueError("run must match ^[A-Za-z0-9-]{1,40}$")
    prefix = f"{code}-{run}"
    if not RUN_PATTERN.fullmatch(prefix):
        raise ValueError("combined run prefix exceeds the W6 limit")

    events = []
    for device_id in DEVICE_IDS:
        serial = device_id.rsplit("-d", 1)[1]
        for sequence in range(1, 4):
            events.append({
                "event_id": f"{prefix}-d{serial}-{sequence:02d}",
                "device_id": device_id,
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "type": "status",
            })
    events.append(dict(events[0]))
    events.append({
        "event_id": f"{prefix}-d99-01",
        "device_id": f"{CODE}-d99",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "type": "status",
    })
    return prefix, events


def previous_prefixes():
    if LAST_RUN_FILE.is_symlink():
        raise ValueError("Refusing a symlink at .local/w06-last-run.json")
    if not LAST_RUN_FILE.exists():
        return set()
    try:
        previous = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Previous W6 run record is unreadable; refusing to overwrite it") from error
    if not isinstance(previous, dict) or not isinstance(previous.get("prefix"), str):
        raise ValueError("Previous W6 run record is invalid; refusing to overwrite it")
    used = previous.get("used_prefixes", [previous["prefix"]])
    if (not isinstance(used, list)
            or any(not isinstance(item, str) or not RUN_PATTERN.fullmatch(item) for item in used)
            or previous["prefix"] not in used):
        raise ValueError("Previous W6 prefix history is invalid; refusing to overwrite it")
    return set(used)


def write_last_run(prefix, puback_ok, used_prefixes):
    if (ROOT / ".local").is_symlink():
        raise ValueError("Refusing a symlink at .local")
    local_dir = ROOT / ".local"
    local_dir.mkdir(mode=0o700, exist_ok=True)
    if LAST_RUN_FILE.is_symlink():
        raise ValueError("Refusing a symlink at .local/w06-last-run.json")
    descriptor, temp_name = tempfile.mkstemp(prefix=".w06-last-run-", dir=local_dir)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "prefix": prefix,
                    "puback_ok": puback_ok,
                    "used_prefixes": sorted(used_prefixes),
                },
                output,
                sort_keys=True,
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, LAST_RUN_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def reserve_run(prefix):
    used_prefixes = previous_prefixes()
    if prefix in used_prefixes:
        raise ValueError("This prefix was already used; choose a new --run value")
    used_prefixes.add(prefix)
    write_last_run(prefix, 0, used_prefixes)


def save_last_run(prefix, puback_ok):
    used_prefixes = previous_prefixes()
    if prefix not in used_prefixes:
        raise ValueError("Run prefix was not reserved before publishing")
    record = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
    if record["prefix"] != prefix:
        raise ValueError("A newer W6 run record exists; refusing to overwrite it")
    write_last_run(prefix, puback_ok, used_prefixes)


class GatewaySimulator:
    def __init__(self, settings):
        self.endpoint = settings["endpoint"]
        self.client = mqtt_check.make_client(settings)
        self.connected = threading.Event()
        self.condition = threading.Condition()
        self.connection_reason = None
        self.publish_reasons = {}
        self.client.on_connect = self.on_connect
        self.client.on_publish = self.on_publish

    def on_connect(self, _client, _userdata, _flags, reason_code, _properties):
        self.connection_reason = mqtt_check.reason_value(reason_code)
        print(f"connack={self.connection_reason}", flush=True)
        self.connected.set()

    def on_publish(self, _client, _userdata, message_id, reason_code, _properties):
        with self.condition:
            self.publish_reasons[message_id] = mqtt_check.reason_value(reason_code)
            self.condition.notify_all()

    def publish_wait(self, topic, event):
        message = self.client.publish(
            topic,
            payload=json.dumps(event, separators=(",", ":")),
            qos=1,
        )
        if message.rc != mqtt_check.mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed with local status {message.rc}")

        deadline = time.monotonic() + 15
        with self.condition:
            while message.mid not in self.publish_reasons:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for PUBACK")
                self.condition.wait(remaining)
            return self.publish_reasons[message.mid]

    def run(self, topic, events, on_puback=None):
        self.client.connect_async(
            self.endpoint,
            8883,
            keepalive=60,
        )
        self.client.loop_start()
        try:
            if not self.connected.wait(15):
                raise TimeoutError("Timed out waiting for MQTT CONNACK")
            if self.connection_reason >= 128:
                return 0
            puback_ok = 0
            for event in events:
                if self.publish_wait(topic, event) < 128:
                    puback_ok += 1
                if on_puback is not None:
                    on_puback(puback_ok)
            return puback_ok
        finally:
            try:
                self.client.disconnect()
            finally:
                self.client.loop_stop()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    prefix, events = build_events(args.code, args.run)
    reserve_run(prefix)
    settings = mqtt_check.load_settings("gw")
    simulator = GatewaySimulator(settings)
    puback_ok = simulator.run(
        f"cxe/{args.code}/gw/events",
        events,
        on_puback=lambda count: save_last_run(prefix, count),
    )
    save_last_run(prefix, puback_ok)
    print(f"puback_ok={puback_ok}/32", flush=True)
    return 0 if puback_ok == 32 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
