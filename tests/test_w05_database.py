"""Offline W5 database contract tests using a PostgreSQL protocol double."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w05_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class FakePostgres:
    class Error(Exception):
        pass

    def __init__(self):
        self.rows = {}
        self.statements = []
        self.connect_args = []
        self.fail_connect = False
        self.module = types.SimpleNamespace(
            Error=self.Error,
            connect=self.connect,
        )

    def connect(self, **kwargs):
        self.connect_args.append(kwargs)
        if self.fail_connect:
            raise self.Error("connection details must not reach HTTP")
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, database):
        self.database = database

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False

    def close(self):
        pass

    def cursor(self):
        return FakeCursor(self.database)


class FakeCursor:
    def __init__(self, database):
        self.database = database
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False

    def execute(self, statement, parameters=None):
        self.database.statements.append((statement, parameters))
        if statement.startswith("CREATE TABLE"):
            return
        if statement.startswith("INSERT INTO events"):
            event_id = parameters[0]
            if event_id not in self.database.rows:
                self.database.rows[event_id] = parameters
                self.result = parameters
            else:
                self.result = None
            return
        if "WHERE event_id = %s" in statement:
            self.result = self.database.rows.get(parameters[0])
            return
        if "ORDER BY received_at DESC" in statement:
            self.result = sorted(self.database.rows.values(),
                                 key=lambda row: row[5], reverse=True)[:50]
            return
        raise AssertionError("unexpected SQL statement")

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class W05DatabaseContract(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.version = root / "version"
        self.version.write_text("c" * 40, encoding="utf-8")
        self.auth_file = root / "app.env"
        self.auth_file.write_text(
            "REPORTER_TOKEN=reporter-test-token\n"
            "OPERATOR_TOKEN=operator-test-token\n"
            "DB_HOST=db.example.invalid\n"
            "DB_NAME=inspection\n"
            "DB_USER=inspection\n"
            "DB_PASSWORD=must-not-be-returned\n",
            encoding="utf-8",
        )
        self.auth_file.chmod(0o600)
        self.database = FakePostgres()
        self.psycopg_patch = patch.dict(sys.modules, {"psycopg2": self.database.module})
        self.psycopg_patch.start()
        self.start_server()

    def tearDown(self):
        self.stop_server()
        self.psycopg_patch.stop()
        self.tempdir.cleanup()

    def start_server(self):
        self.server = service.make_server(self.version, port=0, auth_file=self.auth_file)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def request(self, method, path, token=None, event=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        data = None
        if event is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(event).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_persisted_idempotency_and_verified_tls(self):
        with urllib.request.urlopen(self.base + "/health") as response:
            health = json.load(response)
        self.assertTrue(health["db_configured"])
        self.assertTrue(health["auth_configured"])

        event = {
            "event_id": "group5-ww-w5-0001",
            "device_id": "group5-d01",
            "observed_at": "2026-10-06T10:00:00+08:00",
            "type": "status",
            "note": "Routine inspection passed",
        }
        status, created = self.request("POST", "/events", "reporter-test-token", event)
        self.assertEqual(status, 201)
        self.assertTrue(created["received_at"].endswith("Z"))
        status, duplicate = self.request("POST", "/events", "reporter-test-token", event)
        self.assertEqual(status, 200)
        self.assertEqual(duplicate, created)
        status, detail = self.request(
            "GET", "/events/" + event["event_id"], "operator-test-token")
        self.assertEqual((status, detail), (200, created))
        status, _missing = self.request(
            "GET", "/events/not-present", "operator-test-token")
        self.assertEqual(status, 404)

        changed = dict(event, note="Changed content")
        status, conflict = self.request("POST", "/events", "reporter-test-token", changed)
        self.assertEqual((status, conflict["field"]), (409, "event_id"))
        self.assertEqual(len(self.database.rows), 1)

        insert = next(statement for statement, _ in self.database.statements
                      if statement.startswith("INSERT INTO events"))
        self.assertNotIn(event["event_id"], insert)
        self.assertIn("ON CONFLICT (event_id) DO NOTHING", insert)
        self.assertTrue(any(parameters and parameters[0] == event["event_id"]
                            for _, parameters in self.database.statements))
        self.assertTrue(all(args["sslmode"] == "verify-full"
                            and args["sslrootcert"] == service.RDS_CA_FILE
                            for args in self.database.connect_args))
        self.assertTrue(all(args["password"] == "must-not-be-returned"
                            for args in self.database.connect_args))

        self.stop_server()
        self.start_server()
        status, listing = self.request("GET", "/events", "operator-test-token")
        self.assertEqual(status, 200)
        self.assertEqual(listing["events"], [created])

    def test_database_failure_is_explicit_without_exposing_connection_details(self):
        self.database.fail_connect = True
        status, body = self.request("GET", "/events", "operator-test-token")
        self.assertEqual((status, body), (
            503, {"error": "database_unavailable", "field": "database"}))
        self.assertNotIn("must-not-be-returned", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
