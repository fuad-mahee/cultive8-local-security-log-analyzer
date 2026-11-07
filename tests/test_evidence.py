import unittest, json
import app


class EvidenceTests(unittest.TestCase):
    def records(self, events):
        return app.parse("\n".join(json.dumps(e) for e in events))[0]

    def test_one_failure_success_is_benign(self):
        r = self.records(
            [
                {
                    "client_ip": "a",
                    "username": "u",
                    "auth_result": "invalid_password",
                    "time": "01",
                    "event_id": "synthetic-duplicate",
                },
                {
                    "client_ip": "a",
                    "username": "u",
                    "auth_result": "success",
                    "time": "02",
                },
            ]
        )
        self.assertEqual(app.candidates(r), [])

    def test_distributed_auth_and_changed_identity(self):
        es = [
            {
                "client_ip": "arbitrary",
                "username": "new-user",
                "auth_result": "invalid_password",
                "time": f"2026-01-01T00:00:0{i}Z",
            }
            for i in range(5)
        ]
        es.append(
            {
                "client_ip": "arbitrary",
                "username": "new-user",
                "auth_result": "success",
                "time": "2026-01-01T00:00:09Z",
            }
        )
        c = app.candidates(self.records(es))
        self.assertEqual(c[0]["type"], "Suspected account compromise")
        self.assertEqual(c[0]["identity"], "arbitrary")

    def test_duplicates_do_not_inflate_failure_threshold(self):
        e = {
            "client_ip": "x",
            "username": "u",
            "auth_result": "invalid_password",
            "time": "01",
            "event_id": "synthetic-duplicate",
        }
        self.assertEqual(app.candidates(self.records([e] * 10)), [])

    def test_host_scope_prevents_false_link(self):
        es = [
            {
                "host": "a",
                "client_ip": "x",
                "username": "u",
                "auth_result": "invalid_password",
                "time": f"2026-01-01T00:00:0{i}Z",
            }
            for i in range(5)
        ]
        es.append(
            {
                "host": "b",
                "client_ip": "x",
                "username": "u",
                "auth_result": "success",
                "time": "2026-01-01T00:00:09Z",
            }
        )
        self.assertEqual(app.candidates(self.records(es))[0]["type"], "Brute force")

    def test_encoded_payload(self):
        c = app.candidates(
            self.records(
                [
                    {
                        "client_ip": "x",
                        "path": "/?x=%27%20UNION%20SELECT%20a",
                        "status": 400,
                    }
                ]
            )
        )
        self.assertEqual(c[0]["type"], "SQL injection")

    def test_scans_across_hosts(self):
        es = [
            {"host": str(i), "client_ip": "x", "path": p}
            for i, p in enumerate(["/.env", "/.git/config", "/wp-admin/"])
        ]
        self.assertEqual(app.candidates(self.records(es))[0]["type"], "Scanning")

    def test_operational_error(self):
        self.assertEqual(
            app.candidates(
                self.records(
                    [{"service": "db", "level": "ERROR", "message": "database timeout"}]
                )
            ),
            [],
        )
