#!/usr/bin/env python3
"""Collect W6 MQTT, consumer, database, and device-filter evidence."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import w04_ops


CODE = "group5-ww"
RUN_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,40}$")
PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,40}$")
LAST_RUN_FILE = ROOT / ".local" / "w06-last-run.json"
SECRET_FILE = ROOT / ".local" / "app.env"
COUNT_PATTERN = re.compile(r"^\s*(\d+)\s+result=(created|duplicate|rejected|error)$")
RESULTS = ("created", "duplicate", "rejected", "error")


def make_prefix(code, run):
    if code != CODE or not RUN_PATTERN.fullmatch(code):
        raise ValueError("code must match the configured W6 device code")
    if not RUN_PATTERN.fullmatch(run):
        raise ValueError("run must match ^[A-Za-z0-9-]{1,40}$")
    prefix = f"{code}-{run}"
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise ValueError("combined event prefix exceeds the W6 limit")
    return prefix


def read_last_run(prefix):
    if LAST_RUN_FILE.is_symlink() or not LAST_RUN_FILE.is_file():
        raise ValueError("Missing or unsafe .local/w06-last-run.json")
    record = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("prefix") != prefix:
        raise ValueError("Saved gateway run prefix does not match --code/--run")
    puback_ok = record.get("puback_ok")
    if isinstance(puback_ok, bool) or not isinstance(puback_ok, int) or not 0 <= puback_ok <= 32:
        raise ValueError("Saved gateway PUBACK count is invalid")
    return puback_ok


def read_operator_token():
    if ((ROOT / ".local").is_symlink() or SECRET_FILE.is_symlink()
            or not SECRET_FILE.is_file()):
        raise ValueError("Missing or unsafe .local/app.env")
    if stat.S_IMODE(SECRET_FILE.stat().st_mode) != 0o600:
        raise ValueError(".local/app.env must have mode 600")
    try:
        for line in SECRET_FILE.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key == "OPERATOR_TOKEN" and value:
                return value
    except UnicodeDecodeError as error:
        raise ValueError(".local/app.env is not valid UTF-8; secret contents withheld") from error
    raise ValueError(".local/app.env is missing OPERATOR_TOKEN")


def get_health(public_ip):
    try:
        address = str(ipaddress.IPv4Address(public_ip))
        with urlopen(f"http://{address}/health", timeout=8) as response:
            body = json.load(response)
    except (HTTPError, URLError, TimeoutError, ValueError, OSError) as error:
        raise RuntimeError(f"Could not read host health ({type(error).__name__})") from error
    if (not isinstance(body, dict) or body.get("status") != "ok"
            or not isinstance(body.get("version"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", body["version"])
            or not isinstance(body.get("db_configured"), bool)):
        raise RuntimeError("Host health response does not satisfy the W6 contract")
    return body


def remote_query(prefix):
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise ValueError("Unsafe event prefix; refusing to send it to the host")
    log_query = (
        "set -o pipefail; "
        "journalctl -u inspection-consumer -o cat --no-pager "
        f'| grep -F "event_id={prefix}-" | grep -o "result=[a-z]*" | sort | uniq -c '
        "|| status=$?; test \"${status:-0}\" -le 1"
    )
    database_query = (
        "set -a; . /etc/inspection/app.env; set +a; "
        'PGPASSWORD="$DB_PASSWORD" psql '
        '"host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full '
        'sslrootcert=/etc/inspection/rds-ca.pem" '
        f"-tA -v prefix={prefix}-"
    )
    return (
        f"sudo bash -c '{log_query}'; printf '\\nDB_COUNT='; "
        f"sudo bash -c '{database_query}' <<'SQL'\n"
        "SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';\n"
        "SQL"
    )


def parse_remote_output(output):
    marker = "\nDB_COUNT="
    if marker not in output:
        raise ValueError("Remote evidence response is incomplete")
    log_output, database_output = output.rsplit(marker, 1)
    counts = {result: 0 for result in RESULTS}
    for line in log_output.splitlines():
        if not line.strip():
            continue
        match = COUNT_PATTERN.fullmatch(line)
        if not match:
            raise ValueError("Remote consumer counters contain an unexpected format")
        counts[match.group(2)] += int(match.group(1))
    try:
        database_count = int(database_output.strip())
    except ValueError as error:
        raise ValueError("Remote database count is not an integer") from error
    if database_count < 0:
        raise ValueError("Remote database count is negative")
    return counts, database_count


def collect_remote(public_ip, key_path, prefix):
    deadline = time.monotonic() + 60
    latest = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            latest_counts = ""
            if latest is not None:
                counts, database_count = latest
                latest_counts = (
                    f" (last counts: created={counts['created']} "
                    f"duplicate={counts['duplicate']} rejected={counts['rejected']} "
                    f"error={counts['error']} database={database_count})"
                )
            raise TimeoutError(
                f"Consumer evidence did not reach 32 records within 60 seconds{latest_counts}"
            )
        try:
            output = w04_ops.run_ssh(
                public_ip,
                key_path,
                remote_query(prefix),
                timeout=remaining,
            )
        except TimeoutError as error:
            latest_counts = ""
            if latest is not None:
                counts, database_count = latest
                latest_counts = (
                    f" (last counts: created={counts['created']} "
                    f"duplicate={counts['duplicate']} rejected={counts['rejected']} "
                    f"error={counts['error']} database={database_count})"
                )
            raise TimeoutError(
                f"Consumer evidence did not reach 32 records within 60 seconds{latest_counts}"
            ) from error
        latest = parse_remote_output(output)
        if sum(latest[0].values()) >= 32:
            return latest
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5, remaining))


def get_filtered_events(public_ip, device_id, operator_token, prefix):
    query = urlencode({"device_id": device_id})
    request = Request(
        f"http://{public_ip}/events?{query}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            body = json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"Device filter returned HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read device-filtered events ({type(error).__name__})") from error
    if not isinstance(body, dict):
        raise RuntimeError("Device filter response is not a JSON object")
    events = body.get("events")
    if not isinstance(events, list):
        raise RuntimeError("Device filter response has no event list")
    event_ids = []
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
            raise RuntimeError("Device filter returned an invalid event")
        if event["event_id"].startswith(prefix + "-"):
            if event.get("device_id") != device_id:
                raise RuntimeError("Device filter returned a different device for this prefix")
            event_ids.append(event["event_id"])
    return event_ids


def reconcile(code, run):
    prefix = make_prefix(code, run)
    value = w04_ops.resources()
    if not value.get("public_ip"):
        raise ValueError("resources.json is missing public_ip")
    public_ip = str(ipaddress.IPv4Address(value["public_ip"]))
    health = get_health(public_ip)
    puback_ok = read_last_run(prefix)
    print(
        f"version={health['version']} db_configured={str(health['db_configured']).lower()} "
        f"prefix={prefix}"
    )
    print(f"puback_ok={puback_ok}/32")

    key_path = Path.home() / ".ssh" / "id_ed25519"
    if not key_path.is_file() or stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise ValueError("SSH private key is missing or mode is not 600")
    counts, database_count = collect_remote(value["public_ip"], key_path, prefix)
    print("consumer " + " ".join(f"{name}={counts[name]}" for name in RESULTS))
    print(f"database_count={database_count}")

    device_id = f"{code}-d01"
    event_ids = get_filtered_events(
        public_ip, device_id, read_operator_token(), prefix
    )
    print(f"device_id={device_id} prefix_event_count={len(event_ids)}")
    print("event_ids=" + ",".join(event_ids))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_args()
        reconcile(args.code, args.run)
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
