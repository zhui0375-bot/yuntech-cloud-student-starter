#!/usr/bin/env python3
"""Scoped W4 restore/deploy helpers; AWS calls use scripts/lab.py."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab

REGION = "us-east-1"
EXPECTED_TAGS = {"course": "yuntech-115-1", "week": "w03", "group": "group5", "owner": "ww"}
RESOURCE_FILE = ROOT / ".local" / "resources.json"
SECRET_FILE = ROOT / ".local" / "app.env"


def context():
    value = lab.verify()
    if value["region"] != REGION:
        raise SystemExit(f"W4 requires {REGION}; verified region is {value['region']}")
    return value


def resources():
    if not RESOURCE_FILE.is_file():
        raise SystemExit("Missing .local/resources.json; refusing AWS operations")
    value = json.loads(RESOURCE_FILE.read_text(encoding="utf-8"))
    if (value.get("group") != "group5" or value.get("owner") != "ww"
            or value.get("tags") != EXPECTED_TAGS):
        raise SystemExit("resources.json does not identify the expected group5/ww resources")
    required = ("instance_id", "security_group_id", "key_pair_id", "root_volume_id",
                "network_interface_ids", "source", "commit")
    if any(not value.get(key) for key in required):
        raise SystemExit("resources.json is missing a required resource ID or deployment value")
    return value


def write_resources(value):
    lab.atomic_write(RESOURCE_FILE, json.dumps(value, indent=2, sort_keys=True) + "\n")


def assert_tags(item, label):
    tags = {tag["Key"]: tag["Value"] for tag in item.get("Tags", item.get("TagSet", []))}
    if any(tags.get(key) != expected for key, expected in EXPECTED_TAGS.items()):
        raise SystemExit(f"{label} ownership tags mismatch; refusing operation")


def ingress_signature(group):
    rules = []
    for permission in group.get("IpPermissions", []):
        if (permission.get("UserIdGroupPairs") or permission.get("Ipv6Ranges")
                or permission.get("PrefixListIds")):
            raise SystemExit("listed security group has non-IPv4 ingress; refusing operation")
        for item in permission.get("IpRanges", []):
            rules.append((permission.get("IpProtocol"), permission.get("FromPort"),
                          permission.get("ToPort"), item["CidrIp"]))
    return sorted(rules)


def verified_instance(value):
    resource_checks = [
        (["ec2", "describe-instances", "--instance-ids", value["instance_id"]], "Reservations", "Instances"),
        (["ec2", "describe-security-groups", "--group-ids", value["security_group_id"]], None, "SecurityGroups"),
        (["ec2", "describe-key-pairs", "--key-pair-ids", value["key_pair_id"]], None, "KeyPairs"),
        (["ec2", "describe-volumes", "--volume-ids", value["root_volume_id"]], None, "Volumes"),
    ]
    for arguments, outer, inner in resource_checks:
        response = lab.run_aws(arguments, REGION)
        entries = response.get(outer, [{}])[0].get(inner, []) if outer else response.get(inner, [])
        if len(entries) != 1:
            raise SystemExit(f"listed {inner} ID did not resolve uniquely")
        assert_tags(entries[0], inner.lower())
    for interface_id in value["network_interface_ids"]:
        response = lab.run_aws(["ec2", "describe-network-interfaces", "--network-interface-ids",
                                interface_id], REGION)
        entries = response.get("NetworkInterfaces", [])
        if len(entries) != 1:
            raise SystemExit("listed network interface ID did not resolve uniquely")
        assert_tags(entries[0], "network interface")

    response = lab.run_aws(["ec2", "describe-instances", "--instance-ids", value["instance_id"]], REGION)
    instances = [item for reservation in response.get("Reservations", [])
                 for item in reservation.get("Instances", [])]
    if len(instances) != 1:
        raise SystemExit("listed instance ID did not resolve uniquely")
    instance = instances[0]
    assert_tags(instance, "instance")
    attached = {group.get("GroupId") for group in instance.get("SecurityGroups", [])}
    if value["security_group_id"] not in attached:
        raise SystemExit("listed security group is not attached to the listed instance")
    groups = lab.run_aws(["ec2", "describe-security-groups", "--group-ids",
                          value["security_group_id"]], REGION).get("SecurityGroups", [])
    if len(groups) != 1:
        raise SystemExit("listed security group ID did not resolve uniquely")
    assert_tags(groups[0], "security group")
    expected = sorted([("tcp", 22, 22, value["source"]),
                       ("tcp", 80, 80, value["source"])])
    if ingress_signature(groups[0]) != expected:
        raise SystemExit("security group ingress differs from only TCP 22/80 at the recorded /32")
    return instance


def current_egress():
    try:
        value = urlopen("https://checkip.amazonaws.com", timeout=5).read().decode().strip()
    except (URLError, TimeoutError) as error:
        raise SystemExit("Could not verify current Codespace IPv4; no AWS changes made") from error
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        raise SystemExit("External IP check did not return IPv4; no AWS changes made")
    return value + "/32"


def health(public_ip, commit, require_auth):
    try:
        with urlopen(f"http://{public_ip}/health", timeout=8) as response:
            body = json.load(response)
            if response.status != 200:
                raise SystemExit(f"health returned HTTP {response.status}")
    except (HTTPError, URLError, TimeoutError) as error:
        raise SystemExit(f"health validation failed: {type(error).__name__}") from error
    if body.get("status") != "ok" or body.get("service") != "inspection" or body.get("version") != commit:
        raise SystemExit("health response does not match the committed deployment")
    if require_auth and body.get("auth_configured") is not True:
        raise SystemExit("health auth_configured is not true")
    print(json.dumps({key: body.get(key) for key in
                      ("status", "service", "version", "started_at", "auth_configured")}, sort_keys=True))
    return body


def start(_args):
    context()
    value = resources()
    instance = verified_instance(value)
    state = instance.get("State", {}).get("Name")
    current_source = current_egress()
    if current_source != value["source"]:
        raise SystemExit(f"Codespace source changed: recorded {value['source']}, current {current_source}; obtain review before changing SG")
    if state == "running":
        public_ip = instance.get("PublicIpAddress")
        if not public_ip:
            raise SystemExit("running instance has no public IPv4")
        value["public_ip"] = public_ip
        write_resources(value)
        health(public_ip, value["commit"], require_auth=False)
        print(f"Instance already running; public IPv4 refreshed: {public_ip}")
        return
    if state != "stopped":
        raise SystemExit(f"Expected the preserved instance to be stopped, got {state}; refusing start")

    description = f"""W4 T1 將 Start 既有保留主機（不建立資源）：
EC2：{value['instance_id']}，標籤 course/week/group/owner 已核對為 yuntech-115-1/w03/group5/ww
根 EBS：{value['root_volume_id']}（保留，加密 gp3，Start/Stop 均不刪除）
ENI：{', '.join(value['network_interface_ids'])}
Security Group：{value['security_group_id']}；Key pair：{value['key_pair_id']}
網路暴露：既有 TCP 22/80 僅允許目前 Codespace {current_source}/32；不開新 port、不改 SG。
費用：Start 後 t3.micro 每運行小時計 EC2 運算費，公有 IPv4 配置期間計費；8 GiB gp3 持續計費。實際依 us-east-1 當期 EC2/EBS/IPv4 價格與運行時間。
回收/回復：只停止此 instance；EBS、SG、key pair 保留，Stop 後 public IP 可能釋放。"""
    lab.approve(description, "START")
    lab.run_aws(["ec2", "start-instances", "--instance-ids", value["instance_id"]], REGION)
    lab.run_aws(["ec2", "wait", "instance-running", "--instance-ids", value["instance_id"]], REGION)
    instance = verified_instance(value)
    public_ip = instance.get("PublicIpAddress")
    if not public_ip:
        raise SystemExit("Started instance has no public IPv4; resource IDs remain unchanged")
    value["public_ip"] = public_ip
    write_resources(value)
    health(public_ip, value["commit"], require_auth=False)
    print(f"W4 T1 complete; current public IPv4: {public_ip}")


def load_secret_bytes():
    if not SECRET_FILE.is_file() or stat.S_IMODE(SECRET_FILE.stat().st_mode) != 0o600:
        raise SystemExit(".local/app.env must exist with mode 600; token contents are never displayed")
    payload = SECRET_FILE.read_bytes()
    values = {}
    try:
        for line in payload.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"REPORTER_TOKEN", "OPERATOR_TOKEN"}:
                values[key] = value
    except UnicodeDecodeError as error:
        raise SystemExit("app.env is not valid UTF-8; token contents withheld") from error
    reporter, operator = values.get("REPORTER_TOKEN", ""), values.get("OPERATOR_TOKEN", "")
    if not reporter or not operator or secrets.compare_digest(reporter, operator):
        raise SystemExit("app.env must contain two distinct non-empty tokens; contents withheld")
    return payload


def run_ssh(public_ip, key_path, remote_command, data=None):
    command = ["ssh", "-i", str(key_path), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
               f"ec2-user@{public_ip}", remote_command]
    result = subprocess.run(command, input=data, capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise SystemExit("SSH deployment step failed; output withheld")
    return result.stdout.decode("utf-8", errors="replace")


def deploy(args):
    context()
    value = resources()
    instance = verified_instance(value)
    if instance.get("State", {}).get("Name") != "running":
        raise SystemExit("listed instance must be running before deployment")
    public_ip = instance.get("PublicIpAddress")
    if not public_ip:
        raise SystemExit("running instance has no public IPv4")
    source = current_egress()
    if source != value["source"]:
        raise SystemExit(f"Codespace source changed: recorded {value['source']}, current {source}; obtain review before changing SG")
    secrets_payload = load_secret_bytes()
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "--end-of-options",
                                      args.commit + "^{commit}"], cwd=ROOT, text=True).strip()
    if subprocess.run(["git", "diff", "--quiet", commit, "--", "app/service.py", "deploy/nginx.conf"],
                      cwd=ROOT, check=False).returncode != 0:
        raise SystemExit("app/service.py or deploy/nginx.conf has uncommitted changes; commit and review before deploy")
    if subprocess.run(["git", "diff", "--cached", "--quiet", commit, "--", "app/service.py", "deploy/nginx.conf"],
                      cwd=ROOT, check=False).returncode != 0:
        raise SystemExit("app/service.py or deploy/nginx.conf has staged changes outside the selected commit")
    key_path = Path.home() / ".ssh" / "id_ed25519"
    if not key_path.is_file() or stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise SystemExit("SSH private key is missing or mode is not 600")

    description = f"""W4 T3 將部署到既有主機：
EC2：{value['instance_id']}，目前 public IPv4：{public_ip}，group5/ww 標籤已核對
Commit：{commit}
網路：TCP 22/80 維持既有 {source}/32；不改 SG、不建立資源。
秘密：.local/app.env 權限 600，僅經 SSH stdin 寫到 root:600 的 /etc/inspection/app.env；不進 user data、命令列或輸出。
費用：無新 AWS 資源；主機運行期間仍有 t3.micro、公有 IPv4 與 8 GiB gp3 的既有費用。
確認後用 StrictHostKeyChecking=accept-new 記錄新位址指紋，安裝、注入秘密、重啟服務並驗證 health/auth_configured。
回復：停止同一 instance；服務檔可由上一個已 commit 版本重新部署。"""
    lab.approve(description, "DEPLOY")

    with tempfile.TemporaryDirectory(prefix="w04-user-data-") as directory:
        user_data = Path(directory) / "install.sh"
        subprocess.run(["bash", str(ROOT / "deploy" / "make-user-data.sh"), commit, str(user_data)],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        run_ssh(public_ip, key_path, "sudo bash -s", user_data.read_bytes())
    install_secret = (
        "sudo sh -c 'umask 077; install -d -o root -g root -m 700 /etc/inspection; "
        "cat > /etc/inspection/app.env; chown root:root /etc/inspection/app.env; "
        "chmod 600 /etc/inspection/app.env'"
    )
    run_ssh(public_ip, key_path, install_secret, secrets_payload)
    run_ssh(public_ip, key_path, "sudo systemctl restart inspection.service")
    value["public_ip"] = public_ip
    value["commit"] = commit
    write_resources(value)
    health(public_ip, commit, require_auth=True)
    print(f"W4 deploy complete; host={public_ip}; commit={commit}; token contents withheld")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("start", help="restore the listed stopped W3 instance")
    deploy_parser = subparsers.add_parser("deploy", help="deploy a committed W4 build to the listed running instance")
    deploy_parser.add_argument("--commit", default="HEAD")
    args = parser.parse_args()
    if args.action == "start":
        start(args)
    else:
        deploy(args)


if __name__ == "__main__":
    main()
