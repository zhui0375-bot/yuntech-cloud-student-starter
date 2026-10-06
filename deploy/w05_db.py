#!/usr/bin/env python3
"""Create the private W5 PostgreSQL network and RDS instance in a scoped Lab."""
import ipaddress
import json
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deploy"))
import lab
import w04_ops

REGION = "us-east-1"
RESOURCE_FILE = ROOT / ".local" / "resources.json"
DATABASE_SECRET_FILE = ROOT / ".local" / "db.env"
DB_IDENTIFIER = "inspection-w5-group5-ww"
DB_SUBNET_GROUP = "inspection-w5-group5-ww"
DB_SECURITY_GROUP = "inspection-w5-group5-ww-db"
PRIVATE_SUBNETS = (
    ("db_subnet_1_id", "172.31.96.0/24", "us-east-1a", "w5-db-a"),
    ("db_subnet_2_id", "172.31.97.0/24", "us-east-1b", "w5-db-b"),
)
TAGS = {
    "course": lab.COURSE,
    "week": "w05",
    "group": "group5",
    "owner": "ww",
}


def tags_json(name=None):
    values = dict(TAGS)
    if name:
        values["Name"] = name
    return json.dumps([{"Key": key, "Value": value} for key, value in values.items()])


def resources():
    if not RESOURCE_FILE.is_file():
        raise SystemExit("Missing .local/resources.json; refusing W5 provisioning")
    value = json.loads(RESOURCE_FILE.read_text(encoding="utf-8"))
    if value.get("group") != "group5" or value.get("owner") != "ww":
        raise SystemExit("resources.json does not identify group5/ww; refusing W5 provisioning")
    if value.get("tags") != w04_ops.EXPECTED_TAGS:
        raise SystemExit("W3 ownership tags do not match; refusing W5 provisioning")
    return value


def save_resources(value):
    lab.atomic_write(RESOURCE_FILE, json.dumps(value, indent=2, sort_keys=True) + "\n")


def checked_instance(value):
    verification_resources = dict(value)
    verification_resources["source"] = w04_ops.current_egress()
    instance = w04_ops.verified_instance(verification_resources)
    if instance.get("State", {}).get("Name") != "running":
        raise SystemExit("T2 requires the recorded EC2 instance to be running")
    attached_groups = {item["GroupId"] for item in instance.get("SecurityGroups", [])}
    if value["security_group_id"] not in attached_groups:
        raise SystemExit("Recorded W3 security group is not attached to the host")
    return instance


def tag_map(item):
    return {tag["Key"]: tag["Value"] for tag in item.get("Tags", item.get("TagList", []))}


def verify_owned_resource(item, kind):
    tags = tag_map(item)
    if any(tags.get(key) != expected for key, expected in TAGS.items()):
        raise SystemExit(f"Existing {kind} does not have the expected W5 ownership tags")


def check_subnet_plan(vpc_id, resource_values):
    vpc_response = lab.run_aws(
        ["ec2", "describe-vpcs", "--vpc-ids", vpc_id,
         "--query", "Vpcs[].{Id:VpcId,CIDR:CidrBlock,State:State}"],
        REGION,
    )
    vpcs = vpc_response if isinstance(vpc_response, list) else []
    if len(vpcs) != 1 or vpcs[0].get("State") != "available":
        raise SystemExit("Recorded VPC could not be uniquely verified")
    vpc_network = ipaddress.ip_network(vpcs[0]["CIDR"])
    planned_networks = [ipaddress.ip_network(cidr) for _, cidr, _, _ in PRIVATE_SUBNETS]
    if any(not network.subnet_of(vpc_network) for network in planned_networks):
        raise SystemExit("Planned W5 subnets are outside the verified VPC CIDR")
    if planned_networks[0].overlaps(planned_networks[1]):
        raise SystemExit("Planned W5 subnet CIDRs overlap")

    response = lab.run_aws([
        "ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}",
        "--query", "Subnets[].{Id:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone,State:State}",
    ], REGION)
    existing = response if isinstance(response, list) else []
    for subnet in existing:
        network = ipaddress.ip_network(subnet["CIDR"])
        if any(network.overlaps(planned) for planned in planned_networks):
            expected_id = next((resource_values.get(key) for key, cidr, _, _ in PRIVATE_SUBNETS
                                if cidr == subnet["CIDR"]), None)
            if subnet["Id"] != expected_id:
                raise SystemExit(f"Planned subnet overlaps existing subnet {subnet['Id']}; no changes made")

    zones = lab.run_aws([
        "ec2", "describe-availability-zones", "--filters", "Name=state,Values=available",
        "--query", "AvailabilityZones[].ZoneName",
    ], REGION)
    available = set(zones if isinstance(zones, list) else [])
    if any(az not in available for _, _, az, _ in PRIVATE_SUBNETS):
        raise SystemExit("One or more planned AZs are not available in this account")
    return vpcs[0]["CIDR"], existing


def verify_saved_subnet(value, key, cidr, az):
    response = lab.run_aws(
        ["ec2", "describe-subnets", "--subnet-ids", value[key]],
        REGION,
    )
    items = response.get("Subnets", [])
    if len(items) != 1:
        raise SystemExit(f"Recorded {key} did not resolve uniquely")
    item = items[0]
    verify_owned_resource(item, "subnet")
    if item.get("VpcId") != value["vpc_id"] or item.get("CidrBlock") != cidr:
        raise SystemExit(f"Recorded {key} VPC/CIDR mismatch; refusing reuse")
    if item.get("AvailabilityZone") != az:
        raise SystemExit(f"Recorded {key} AZ mismatch; refusing reuse")
    if item.get("MapPublicIpOnLaunch") is not False:
        lab.run_aws([
            "ec2", "modify-subnet-attribute", "--subnet-id", item["SubnetId"],
            "--no-map-public-ip-on-launch",
        ], REGION)
    return item["SubnetId"]


def ensure_subnet(value, key, cidr, az, name):
    if value.get(key):
        return verify_saved_subnet(value, key, cidr, az)
    response = lab.run_aws([
        "ec2", "create-subnet", "--vpc-id", value["vpc_id"],
        "--cidr-block", cidr, "--availability-zone", az,
        "--tag-specifications",
        json.dumps([{"ResourceType": "subnet", "Tags": json.loads(tags_json(name))}]),
    ], REGION)
    subnet_id = response.get("Subnet", {}).get("SubnetId")
    if not subnet_id:
        raise SystemExit("CreateSubnet did not return an ID; inspect the account before retrying")
    value[key] = subnet_id
    save_resources(value)
    lab.run_aws([
        "ec2", "modify-subnet-attribute", "--subnet-id", subnet_id,
        "--no-map-public-ip-on-launch",
    ], REGION)
    return subnet_id


def ensure_private_route_table(value, vpc_cidr):
    route_table_id = value.get("db_route_table_id")
    if route_table_id:
        response = lab.run_aws(
            ["ec2", "describe-route-tables", "--route-table-ids", route_table_id],
            REGION,
        )
        items = response.get("RouteTables", [])
        if len(items) != 1:
            raise SystemExit("Recorded W5 route table did not resolve uniquely")
        item = items[0]
        verify_owned_resource(item, "route table")
        if item.get("VpcId") != value["vpc_id"]:
            raise SystemExit("Recorded W5 route table belongs to a different VPC")
        routes = item.get("Routes", [])
        if len(routes) != 1 or routes[0].get("DestinationCidrBlock") != vpc_cidr:
            raise SystemExit("W5 route table is not restricted to the VPC local route")
        return route_table_id
    response = lab.run_aws([
        "ec2", "create-route-table", "--vpc-id", value["vpc_id"],
        "--tag-specifications",
        json.dumps([{"ResourceType": "route-table",
                     "Tags": json.loads(tags_json("w5-private-db"))}]),
    ], REGION)
    route_table_id = response.get("RouteTable", {}).get("RouteTableId")
    if not route_table_id:
        raise SystemExit("CreateRouteTable did not return an ID; inspect before retrying")
    value["db_route_table_id"] = route_table_id
    save_resources(value)
    return route_table_id


def ensure_subnet_association(value, route_table_id, subnet_id, key):
    associations = value.get("db_route_association_ids", {})
    if associations.get(key):
        response = lab.run_aws([
            "ec2", "describe-route-tables", "--route-table-ids", route_table_id,
        ], REGION)
        items = response.get("RouteTables", [])
        if len(items) != 1 or not any(
            association.get("RouteTableAssociationId") == associations[key]
            and association.get("SubnetId") == subnet_id
            for association in items[0].get("Associations", [])
        ):
            raise SystemExit(f"Saved route association {key} could not be verified")
        return
    response = lab.run_aws([
        "ec2", "associate-route-table", "--route-table-id", route_table_id,
        "--subnet-id", subnet_id,
    ], REGION)
    association_id = response.get("AssociationId")
    if not association_id:
        raise SystemExit("AssociateRouteTable did not return an ID")
    associations[key] = association_id
    value["db_route_association_ids"] = associations
    save_resources(value)


def ensure_db_subnet_group(value, subnet_ids):
    if value.get("db_subnet_group_name"):
        result = lab.run_aws([
            "rds", "describe-db-subnet-groups", "--db-subnet-group-name",
            value["db_subnet_group_name"],
        ], REGION)
        groups = result.get("DBSubnetGroups", [])
        if len(groups) != 1:
            raise SystemExit("Recorded DB subnet group did not resolve uniquely")
        group_arn = groups[0].get("DBSubnetGroupArn")
        if not group_arn:
            raise SystemExit("Recorded DB subnet group did not return its ARN")
        tags = lab.run_aws([
            "rds", "list-tags-for-resource", "--resource-name", group_arn,
        ], REGION)
        verify_owned_resource({"TagList": tags.get("TagList", [])}, "DB subnet group")
        configured = {item["SubnetIdentifier"] for item in groups[0].get("Subnets", [])}
        if configured != set(subnet_ids):
            raise SystemExit("Recorded DB subnet group subnet IDs differ from the planned pair")
        return value["db_subnet_group_name"]
    lab.run_aws([
        "rds", "create-db-subnet-group",
        "--db-subnet-group-name", DB_SUBNET_GROUP,
        "--db-subnet-group-description", "Private W5 inspection database subnets",
        "--subnet-ids", *subnet_ids,
        "--tags", tags_json("w5-private-db"),
    ], REGION)
    value["db_subnet_group_name"] = DB_SUBNET_GROUP
    save_resources(value)
    return DB_SUBNET_GROUP


def verify_database_security_group(group, value):
    verify_owned_resource(group, "security group")
    if group.get("VpcId") != value["vpc_id"]:
        raise SystemExit("W5 DB security group belongs to another VPC")
    expected = [("tcp", 5432, 5432, value["security_group_id"])]
    actual = []
    for permission in group.get("IpPermissions", []):
        if permission.get("IpProtocol") != "tcp" or permission.get("FromPort") != 5432 or permission.get("ToPort") != 5432:
            raise SystemExit("W5 DB security group has an unexpected inbound rule")
        if permission.get("Ipv6Ranges") or permission.get("PrefixListIds") or permission.get("IpRanges"):
            raise SystemExit("W5 DB security group inbound rule must reference only the host security group")
        actual.extend(("tcp", 5432, 5432, pair["GroupId"])
                      for pair in permission.get("UserIdGroupPairs", []))
    if sorted(actual) != sorted(expected):
        raise SystemExit("W5 DB security group must have exactly one 5432 rule from the recorded host SG")


def ensure_database_security_group(value):
    if value.get("db_security_group_id"):
        response = lab.run_aws([
            "ec2", "describe-security-groups", "--group-ids",
            value["db_security_group_id"],
        ], REGION)
        groups = response.get("SecurityGroups", [])
        if len(groups) != 1:
            raise SystemExit("Recorded W5 DB security group did not resolve uniquely")
        group = groups[0]
        verify_database_security_group(group, value)
        return group["GroupId"]

    result = lab.run_aws([
        "ec2", "create-security-group",
        "--group-name", DB_SECURITY_GROUP,
        "--description", "W5 PostgreSQL ingress from the recorded inspection host SG only",
        "--vpc-id", value["vpc_id"],
        "--tag-specifications",
        json.dumps([{"ResourceType": "security-group",
                     "Tags": json.loads(tags_json(DB_SECURITY_GROUP))}]),
    ], REGION)
    group_id = result.get("GroupId")
    if not group_id:
        raise SystemExit("CreateSecurityGroup did not return an ID; inspect before retrying")
    value["db_security_group_id"] = group_id
    save_resources(value)
    lab.run_aws([
        "ec2", "authorize-security-group-ingress", "--group-id", group_id,
        "--protocol", "tcp", "--port", "5432",
        "--source-group", value["security_group_id"],
    ], REGION)
    group = lab.run_aws([
        "ec2", "describe-security-groups", "--group-ids", group_id,
    ], REGION).get("SecurityGroups", [])
    if len(group) != 1:
        raise SystemExit("Created W5 DB security group could not be read back")
    verify_database_security_group(group[0], value)
    return group_id


def verify_db_instance(value, wait=False):
    if wait:
        deadline = time.monotonic() + 25 * 60
        while True:
            result = lab.run_aws([
                "rds", "describe-db-instances",
                "--db-instance-identifier", DB_IDENTIFIER,
            ], REGION)
            instances = result.get("DBInstances", [])
            if len(instances) != 1:
                raise SystemExit("W5 DB instance did not resolve uniquely")
            state = instances[0].get("DBInstanceStatus")
            if state == "available":
                break
            if state in {"failed", "incompatible-restore", "storage-full"}:
                raise SystemExit(f"RDS creation stopped in state {state}; inspect exact resource IDs")
            if time.monotonic() >= deadline:
                raise SystemExit("RDS is still creating after 25 minutes; do not rerun the script")
            time.sleep(30)

    result = lab.run_aws([
        "rds", "describe-db-instances",
        "--db-instance-identifier", DB_IDENTIFIER,
        "--query", "DBInstances[].{Id:DBInstanceIdentifier,Arn:DBInstanceArn,"
                   "Status:DBInstanceStatus,Public:PubliclyAccessible,Encrypted:StorageEncrypted,"
                   "Class:DBInstanceClass,Storage:AllocatedStorage,Endpoint:Endpoint.Address,"
                   "SubnetGroup:DBSubnetGroup.DBSubnetGroupName,"
                   "SecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId,"
                   "MultiAZ:MultiAZ,Engine:Engine,DBName:DBName}",
    ], REGION)
    instances = result if isinstance(result, list) else []
    if len(instances) != 1:
        raise SystemExit("W5 DB instance did not resolve uniquely")
    instance = instances[0]
    if (instance.get("Public") is not False or instance.get("Encrypted") is not True
            or instance.get("Class") != "db.t3.micro" or instance.get("Storage") != 20
            or instance.get("MultiAZ") is not False or instance.get("DBName") != "inspection"
            or instance.get("SubnetGroup") != DB_SUBNET_GROUP
            or value["db_security_group_id"] not in instance.get("SecurityGroups", [])):
        raise SystemExit("RDS settings do not meet the W5 private/encryption/sizing contract")
    tags = lab.run_aws([
        "rds", "list-tags-for-resource", "--resource-name", instance["Arn"],
    ], REGION)
    verify_owned_resource({"TagList": tags.get("TagList", [])}, "RDS instance")
    value["db_instance_identifier"] = instance["Id"]
    value["db_instance_arn"] = instance["Arn"]
    value["db_endpoint"] = instance["Endpoint"]
    value["db_status"] = instance["Status"]
    save_resources(value)
    return instance


def database_password():
    if not DATABASE_SECRET_FILE.exists():
        return secrets.token_urlsafe(36)
    if stat.S_IMODE(DATABASE_SECRET_FILE.stat().st_mode) != 0o600:
        raise SystemExit(".local/db.env exists but is not mode 600; contents withheld")
    values = {}
    for line in DATABASE_SECRET_FILE.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"}:
            values[key] = value
    if not values.get("DB_PASSWORD"):
        raise SystemExit(".local/db.env has no saved DB_PASSWORD; contents withheld")
    return values["DB_PASSWORD"]


def write_database_secret(endpoint, password):
    content = (
        f"DB_HOST={endpoint}\nDB_NAME=inspection\n"
        f"DB_USER=inspection_admin\nDB_PASSWORD={password}\n"
    )
    lab.atomic_write(DATABASE_SECRET_FILE, content)
    if stat.S_IMODE(DATABASE_SECRET_FILE.stat().st_mode) != 0o600:
        raise SystemExit(".local/db.env mode is not 600; stop and inspect the file permissions")


def main():
    ctx = lab.verify()
    if ctx["region"] != REGION:
        raise SystemExit(f"W5 provisioning is restricted to {REGION}")
    value = resources()
    instance = checked_instance(value)
    vpc_cidr, _ = check_subnet_plan(value["vpc_id"], value)

    if value.get("db_instance_identifier") and DATABASE_SECRET_FILE.is_file():
        result = verify_db_instance(value, wait=False)
        print(json.dumps({
            "db_instance_identifier": result["Id"],
            "status": result["Status"],
            "publicly_accessible": result["Public"],
            "encrypted": result["Encrypted"],
            "endpoint_saved_to_private_file": True,
        }, sort_keys=True))
        return
    description = f"""W5 T2 will create exactly these resources in us-east-1:
VPC: {value['vpc_id']} ({vpc_cidr}); existing W3 EC2 {value['instance_id']} and host SG {value['security_group_id']} are reused, not modified.
Subnets: 172.31.96.0/24 in us-east-1a and 172.31.97.0/24 in us-east-1b; both private, no public-IP assignment.
Route table: one new table in the same VPC with only the automatic VPC-local route; explicit association to both new subnets.
RDS subnet group: {DB_SUBNET_GROUP}, using only the two new subnets.
DB security group: {DB_SECURITY_GROUP}; inbound only TCP 5432 from existing host SG {value['security_group_id']}; no public/Codespace access.
RDS: PostgreSQL {DB_IDENTIFIER}, db.t3.micro, 20 GiB gp3, encrypted, single-AZ, PubliclyAccessible=false, initial database inspection.
Secret: generate one password and write .local/db.env with mode 600; password is supplied via a protected temporary AWS CLI input file, never argv/output/Git.
Budget: RDS instance-hours and 20 GiB gp3 storage are billable while running; subnet/route/SG resources have no hourly charge. Confirm the current us-east-1 RDS estimate and your Learner Lab remaining budget before authorizing; no numeric estimate has been verified here.
Network exposure: no public DB endpoint; port 5432 reachable only from the existing EC2 host SG. The host SG is not changed.
Recovery: record every created ID in .local/resources.json immediately. At T4 stop only this DB and the listed EC2; retain the two private subnets, their route table/associations, subnet group and DB SG. Do not delete or broadly clean up resources."""
    lab.approve(description, "CREATE-W5-RDS")

    password = database_password()
    if not DATABASE_SECRET_FILE.exists():
        write_database_secret("pending", password)
    subnet_ids = []
    for key, cidr, az, name in PRIVATE_SUBNETS:
        subnet_ids.append(ensure_subnet(value, key, cidr, az, name))
    route_table_id = ensure_private_route_table(value, vpc_cidr)
    for subnet_id, key in zip(subnet_ids, ("subnet_a", "subnet_b")):
        ensure_subnet_association(value, route_table_id, subnet_id, key)
    subnet_group = ensure_db_subnet_group(value, subnet_ids)
    db_sg = ensure_database_security_group(value)

    try:
        existing_db = lab.run_aws([
            "rds", "describe-db-instances", "--db-instance-identifier", DB_IDENTIFIER,
            "--query", "DBInstances[].{Id:DBInstanceIdentifier,Arn:DBInstanceArn,Status:DBInstanceStatus}",
        ], REGION)
    except lab.LabError as error:
        if "DBInstanceNotFound" not in str(error):
            raise
        existing_db = []
    existing_instances = existing_db if isinstance(existing_db, list) else []
    if existing_instances:
        if len(existing_instances) != 1:
            raise SystemExit("An ambiguous RDS instance with the W5 identifier exists")
        value["db_instance_identifier"] = existing_instances[0]["Id"]
        value["db_instance_arn"] = existing_instances[0]["Arn"]
        value["db_status"] = existing_instances[0]["Status"]
        save_resources(value)
    if not value.get("db_instance_identifier"):
        request = {
            "DBInstanceIdentifier": DB_IDENTIFIER,
            "AllocatedStorage": 20,
            "DBInstanceClass": "db.t3.micro",
            "Engine": "postgres",
            "MasterUsername": "inspection_admin",
            "MasterUserPassword": password,
            "DBName": "inspection",
            "VpcSecurityGroupIds": [db_sg],
            "DBSubnetGroupName": subnet_group,
            "PubliclyAccessible": False,
            "StorageType": "gp3",
            "StorageEncrypted": True,
            "MultiAZ": False,
            "BackupRetentionPeriod": 0,
            "Tags": json.loads(tags_json(DB_IDENTIFIER)),
        }
        with tempfile.TemporaryDirectory(prefix="w5-rds-", dir=ROOT / ".local") as directory:
            request_file = Path(directory) / "create-db.json"
            request_file.write_text(json.dumps(request), encoding="utf-8")
            request_file.chmod(0o600)
            result = lab.run_aws([
                "rds", "create-db-instance", "--cli-input-json",
                request_file.resolve().as_uri(),
            ], REGION)
        db_instance = result.get("DBInstance", {})
        if db_instance.get("DBInstanceIdentifier") != DB_IDENTIFIER:
            raise SystemExit("CreateDBInstance did not confirm the expected identifier; inspect before retrying")
        value["db_instance_identifier"] = DB_IDENTIFIER
        value["db_instance_arn"] = db_instance.get("DBInstanceArn")
        value["db_status"] = db_instance.get("DBInstanceStatus")
        save_resources(value)

    result = verify_db_instance(value, wait=True)
    if not result.get("Endpoint"):
        raise SystemExit("RDS is available but has no endpoint; do not retry creation")
    write_database_secret(result["Endpoint"], password)
    print(json.dumps({
        "db_instance_identifier": result["Id"],
        "status": result["Status"],
        "publicly_accessible": result["Public"],
        "encrypted": result["Encrypted"],
        "engine": result["Engine"],
        "instance_class": result["Class"],
        "storage_gib": result["Storage"],
        "endpoint_saved_to_private_file": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
