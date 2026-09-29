"""Offline tests for W4 deployment network-scope guards."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w04_ops", ROOT / "deploy/w04_ops.py")
w04_ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w04_ops)


class IngressScopeTests(unittest.TestCase):
    def test_accepts_only_the_recorded_ipv4_http_and_ssh_rules(self):
        source = "23.97.62.135/32"
        group = {"IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "UserIdGroupPairs": [], "IpRanges": [{"CidrIp": source}],
             "Ipv6Ranges": [], "PrefixListIds": []},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "UserIdGroupPairs": [], "IpRanges": [{"CidrIp": source}],
             "Ipv6Ranges": [], "PrefixListIds": []},
        ]}
        self.assertEqual(w04_ops.ingress_signature(group), sorted([
            ("tcp", 22, 22, source), ("tcp", 80, 80, source),
        ]))

    def test_rejects_ipv6_and_security_group_references(self):
        for permission in (
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "UserIdGroupPairs": [{"GroupId": "sg-other"}]},
        ):
            with self.subTest(permission=permission):
                with self.assertRaisesRegex(SystemExit, "non-IPv4 ingress"):
                    w04_ops.ingress_signature({"IpPermissions": [permission]})


if __name__ == "__main__":
    unittest.main()