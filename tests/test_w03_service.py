"""Offline public-contract checks; no AWS calls or classroom answers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w03_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
FIXTURES = ROOT / "tests" / "fixtures"


class ServiceContract(unittest.TestCase):
    def test_health_version_and_unknown_route(self):
        with tempfile.TemporaryDirectory() as td:
            version = Path(td) / "version"
            version.write_text("a" * 40)
            server = service.make_server(version, port=0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                base = "http://127.0.0.1:" + str(server.server_port)
                with urllib.request.urlopen(base + "/health") as response:
                    result = json.load(response)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(result["version"], "a" * 40)
                    self.assertEqual(result["service"], "inspection")
                    self.assertEqual(result["status"], "ok")
                    self.assertTrue(result["started_at"].endswith("Z"))
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + "/unknown")
                self.assertEqual(caught.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)

    def test_invalid_deployment_version_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            version = Path(td) / "version"
            version.write_text("uncommitted")
            with self.assertRaises(ValueError):
                service.make_server(version, port=0)


class EventsContract(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.version = root / "version"
        self.version.write_text("b" * 40)
        self.auth_file = root / "app.env"
        self.auth_file.write_text("REPORTER_TOKEN=reporter-test-token\nOPERATOR_TOKEN=operator-test-token\n")
        self.auth_file.chmod(0o600)
        self.server = service.make_server(self.version, port=0, auth_file=self.auth_file)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, method, path, token=None, event=None, content_type="application/json"):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        data = None
        if event is not None:
            data = event if isinstance(event, bytes) else json.dumps(event).encode("utf-8")
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            parsed = json.loads(body) if response.headers.get_content_type() == "application/json" else body.decode()
            return response.status, parsed

    def fixture(self, name):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def test_health_reports_auth_configuration(self):
        status, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["auth_configured"])
        self.assertEqual(body["version"], "b" * 40)

    def test_reporter_create_duplicate_and_operator_reads(self):
        event = self.fixture("event-success.json")
        status, created = self.request("POST", "/events", "reporter-test-token", event)
        self.assertEqual(status, 201)
        self.assertTrue(created["received_at"].endswith("Z"))
        status, duplicate = self.request("POST", "/events", "reporter-test-token", event)
        self.assertEqual((status, duplicate["field"]), (409, "event_id"))
        status, listing = self.request("GET", "/events", "operator-test-token")
        self.assertEqual(status, 200)
        self.assertEqual(listing["events"][0]["event_id"], event["event_id"])
        status, detail = self.request("GET", "/events/" + event["event_id"], "operator-test-token")
        self.assertEqual(status, 200)
        self.assertEqual(detail["received_at"], created["received_at"])

    def test_authentication_and_role_checks_precede_validation(self):
        malformed = b"not-json"
        status, body = self.request("POST", "/events", event=malformed, content_type="text/plain")
        self.assertEqual((status, body["error"]), (401, "unauthorized"))
        status, body = self.request("POST", "/events", "operator-test-token",
                                    self.fixture("event-success.json"))
        self.assertEqual((status, body["error"]), (403, "forbidden"))
        status, body = self.request("GET", "/events", "reporter-test-token")
        self.assertEqual((status, body["error"]), (403, "forbidden"))

    def test_fixture_validation_and_content_limits(self):
        bad_time = self.fixture("event-no-timezone.json")
        status, body = self.request("POST", "/events", "reporter-test-token", bad_time)
        self.assertEqual((status, body["field"]), (400, "observed_at"))
        extra = self.fixture("event-extra-field.json")
        status, body = self.request("POST", "/events", "reporter-test-token", extra)
        self.assertEqual((status, body["field"]), (400, "unexpected"))
        malformed_type = self.fixture("event-success.json")
        malformed_type["type"] = []
        status, body = self.request("POST", "/events", "reporter-test-token", malformed_type)
        self.assertEqual((status, body["field"]), (400, "type"))
        valid = self.fixture("event-success.json")
        status, body = self.request("POST", "/events", "reporter-test-token", valid,
                                    content_type="text/plain")
        self.assertEqual((status, body["field"]), (400, "content_type"))
        status, body = self.request("POST", "/events", "reporter-test-token", b"x" * 4097)
        self.assertEqual((status, body["field"]), (400, "body"))

    def test_display_page_uses_text_content_and_no_browser_storage(self):
        status, html = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("textContent", html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("localStorage", html)
        self.assertNotIn("sessionStorage", html)
        self.assertNotIn("?token=", html)
