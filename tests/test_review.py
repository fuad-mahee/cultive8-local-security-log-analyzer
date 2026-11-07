import unittest, json
from unittest.mock import patch
import app


class ReviewTests(unittest.TestCase):
    def test_model_discovery_survives_without_rule_match(self):
        rows, _ = app.parse(
            '{"client_ip":"synthetic","message":"unusual application event"}'
        )
        finding = {"type": "Unauthorized access", "identity": "synthetic", "lines": [1]}
        self.assertEqual(app.candidates(rows), [])
        self.assertEqual(app.review_proposals(rows, [finding])[0]["origin"], "model")

    def test_same_ip_different_hosts_not_merged(self):
        f = {
            "type": "Brute force",
            "severity": "Medium",
            "identity": "synthetic",
            "lines": [1],
            "reason": "r",
            "action": "a",
            "outcome": "attempted",
        }
        rows = {
            1: {"event": {"host": "one", "username": "a"}, "source_lines": [1]},
            2: {"event": {"host": "two", "username": "a"}, "source_lines": [2]},
        }
        self.assertEqual(len(app.consolidate([f, dict(f, lines=[2])], rows)), 2)

    def test_different_attacks_with_shared_line_not_merged(self):
        f = {
            "type": "Scanning",
            "severity": "Medium",
            "identity": "synthetic",
            "lines": [1],
            "reason": "r",
            "action": "a",
            "outcome": "attempted",
        }
        rows = {1: {"event": {}, "source_lines": [1]}}
        self.assertEqual(
            len(app.consolidate([f, dict(f, type="SQL injection")], rows)), 2
        )

    def test_apache_request_fields(self):
        r, w = app.parse(
            '192.0.2.42 - - [01/Jan/2026:00:00:00 +0000] "GET /?id=1 HTTP/1.1" 403 10'
        )
        self.assertEqual(r[0]["event"]["status"], 403)
        self.assertEqual(r[0]["event"]["client_ip"], "192.0.2.42")

    def test_bad_rate_types_do_not_crash(self):
        r, w = app.parse(
            '{"client_ip":"synthetic","requests_in_window":"lots","window_seconds":null}'
        )
        self.assertEqual(app.candidates(r), [])

    def test_repeated_unidentified_text_is_not_deduplicated(self):
        records, _ = app.parse("failed login\nfailed login")
        self.assertEqual(len(records), 2)

    def test_success_before_later_failures_is_still_correlated(self):
        events = [
            {
                "client_ip": "synthetic",
                "username": "u",
                "time": f"2026-01-01T00:00:0{i}Z",
                "auth_result": "invalid_password",
            }
            for i in range(5)
        ]
        events += [
            {
                "client_ip": "synthetic",
                "username": "u",
                "time": "2026-01-01T00:00:05Z",
                "auth_result": "success",
            },
            {
                "client_ip": "synthetic",
                "username": "u",
                "time": "2026-01-01T00:00:09Z",
                "auth_result": "invalid_password",
            },
        ]
        rows, _ = app.parse("\n".join(json.dumps(e) for e in reversed(events)))
        self.assertEqual(
            app.candidates(rows)[0]["type"], "Suspected account compromise"
        )

    def test_review_has_counts_for_sparse_representative_evidence(self):
        events = [
            {
                "client_ip": "synthetic",
                "username": "u",
                "time": str(i),
                "auth_result": "invalid_password",
            }
            for i in range(12)
        ]
        events.append(
            {"client_ip": "synthetic", "username": "u", "auth_result": "success"}
        )
        records, _ = app.parse("\n".join(json.dumps(e) for e in events))
        facts = app.review_memory(records, [records[0], records[-2], records[-1]])
        self.assertEqual(
            next(f["count"] for f in facts if f["auth_result"] == "invalid_password"),
            12,
        )
