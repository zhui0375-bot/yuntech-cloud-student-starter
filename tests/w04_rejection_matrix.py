#!/usr/bin/env python3
"""Run the seven W4 authorization and validation cases against the current host."""
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deploy"))
import lab
import w04_ops

REGION = "us-east-1"
TAGS = {"course": "yuntech-115-1", "week": "w03", "group": "group5", "owner": "ww"}


def read_secrets(path):
    path = Path(path)
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit(".local/app.env must exist with mode 600; token contents are not displayed")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"REPORTER_TOKEN", "OPERATOR_TOKEN"}:
            values[key] = value
    reporter = values.get("REPORTER_TOKEN", "")
    operator = values.get("OPERATOR_TOKEN", "")
    if not reporter or not operator or secrets.compare_digest(reporter, operator):
        raise SystemExit("app.env must contain two distinct non-empty tokens")
    return reporter, operator


def current_base_url(resources):
    context = lab.verify()
    if context["region"] != REGION:
        raise SystemExit(f"W4 requires {REGION}; got {context['region']}")
    instance_id = resources["instance_id"]
    response = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], REGION)
    instances = [item for reservation in response.get("Reservations", [])
                 for item in reservation.get("Instances", [])]
    if len(instances) != 1:
        raise SystemExit("listed W3 instance did not resolve uniquely")
    instance = instances[0]
    w04_ops.assert_tags(instance, "instance")
    if instance.get("State", {}).get("Name") != "running":
        raise SystemExit("W4 matrix requires the listed instance to be running")
    sg_ids = {item["GroupId"] for item in instance.get("SecurityGroups", [])}
    if resources["security_group_id"] not in sg_ids:
        raise SystemExit("listed W3 Security Group is not attached to the instance")
    public_ip = instance.get("PublicIpAddress")
    if not public_ip:
        raise SystemExit("listed running instance has no public IPv4")
    resources["public_ip"] = public_ip
    w04_ops.write_resources(resources)
    return f"http://{public_ip}"


def send(base_url, method, path, token=None, payload=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(base_url + path, data=data, headers=headers, method=method)
    try:
        response = urlopen(request, timeout=8)
    except HTTPError as error:
        response = error
    except URLError as error:
        raise SystemExit(f"request failed: {type(error).__name__}; details withheld") from error
    with response:
        body = response.read()
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = {"body": "non-json response omitted"}
        return response.status, parsed


def safe_body(body, tokens):
    rendered = json.dumps(body, ensure_ascii=False, sort_keys=True)
    for token in tokens:
        rendered = rendered.replace(token, "[REDACTED]")
    return rendered


def main():
    resources = w04_ops.resources()
    if resources.get("group") != "group5" or resources.get("owner") != "ww" or resources.get("tags") != TAGS:
        raise SystemExit("resources.json does not identify the expected group5/ww deployment")
    reporter, operator = read_secrets(ROOT / ".local" / "app.env")
    tokens = (reporter, operator)
    base_url = current_base_url(resources)
    health_status, health = send(base_url, "GET", "/health")
    if health_status != 200 or not health.get("auth_configured"):
        raise SystemExit("/health must return 200 with auth_configured=true before matrix")
    print(json.dumps({"version": health.get("version"), "auth_configured": health.get("auth_configured")},
                     ensure_ascii=False, sort_keys=True))

    success = json.loads((ROOT / "tests/fixtures/event-success.json").read_text(encoding="utf-8"))
    success["event_id"] += "-" + secrets.token_hex(3)
    missing_timezone = json.loads((ROOT / "tests/fixtures/event-no-timezone.json").read_text(encoding="utf-8"))
    cases = [
        (1, 201, "POST", "/events", reporter, success),
        (2, 401, "POST", "/events", None, success),
        (3, 403, "POST", "/events", operator, success),
        (4, 400, "POST", "/events", reporter, missing_timezone),
        (5, 409, "POST", "/events", reporter, success),
        (6, 403, "GET", "/events", reporter, None),
        (7, 200, "GET", "/events", operator, None),
    ]
    failed = False
    for number, expected, method, path, token, payload in cases:
        status, body = send(base_url, method, path, token, payload)
        valid = status == expected
        if number == 4:
            valid = valid and body.get("field") == "observed_at"
        if number == 7:
            valid = valid and any(item.get("event_id") == success["event_id"]
                                  for item in body.get("events", []))
        failed = failed or not valid
        print(f"#{number} expected={expected} actual={status} body={safe_body(body, tokens)}")
    if failed:
        raise SystemExit("one or more W4 matrix expectations failed")


if __name__ == "__main__":
    main()
