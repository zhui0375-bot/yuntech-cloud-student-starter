"""Offline W5 provisioning-guard tests; these tests never call AWS."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w05_db", ROOT / "deploy/w05_db.py")
w05_db = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w05_db)


class DatabaseSecurityGroupTests(unittest.TestCase):
    def setUp(self):
        self.resources = {
            "vpc_id": "vpc-123",
            "security_group_id": "sg-host",
        }
        self.group = {
            "VpcId": "vpc-123",
            "Tags": [
                {"Key": key, "Value": value}
                for key, value in w05_db.TAGS.items()
            ],
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": "sg-host"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "IpRanges": [],
            }],
        }

    def test_accepts_only_tcp_5432_from_the_recorded_host_group(self):
        w05_db.verify_database_security_group(self.group, self.resources)

    def test_rejects_public_cidr_or_additional_ingress(self):
        public = {
            **self.group,
            "IpPermissions": [{
                **self.group["IpPermissions"][0],
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }
        with self.assertRaisesRegex(SystemExit, "must reference only"):
            w05_db.verify_database_security_group(public, self.resources)

        extra_port = {
            **self.group,
            "IpPermissions": [
                *self.group["IpPermissions"],
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22},
            ],
        }
        with self.assertRaisesRegex(SystemExit, "unexpected inbound rule"):
            w05_db.verify_database_security_group(extra_port, self.resources)


if __name__ == "__main__":
    unittest.main()
