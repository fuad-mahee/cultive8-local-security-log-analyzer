import unittest
import app


class CoreTests(unittest.TestCase):
    def test_duplicates(self):
        rows, w = app.parse('{"client_ip":"a"}\n\n{"client_ip":"a"}')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_lines"], [1, 3])

    def test_plain_text(self):
        rows, w = app.parse("raw error")
        self.assertEqual(rows[0]["line"], 1)
        self.assertTrue(w)

    def test_persistent_memory(self):
        rows, w = app.parse(
            '{"client_ip":"x","username":"u","auth_result":"invalid_password"}\n{"client_ip":"y"}\n{"client_ip":"x","username":"u","auth_result":"success"}'
        )
        m = app.memory(rows, [rows[-1]])
        self.assertEqual(m[0]["count"], 1)
        self.assertEqual(m[0]["lines"], [1])

    def test_invalid_evidence(self):
        f = {
            "type": "scan",
            "severity": "High",
            "identity": "x",
            "lines": [99],
            "reason": "r",
            "action": "a",
            "outcome": "attempted",
        }
        with self.assertRaises(ValueError):
            app.validate({"findings": [f]}, {1})
        f["lines"] = [True]
        with self.assertRaises(ValueError):
            app.validate({"findings": [f]}, {1})

    def test_consolidation(self):
        f = {
            "type": "scan",
            "severity": "Medium",
            "identity": "x",
            "lines": [1],
            "reason": "r",
            "action": "a",
            "outcome": "blocked",
        }
        rows = {
            1: {"event": {}, "source_lines": [1]},
            2: {"event": {}, "source_lines": [2]},
        }
        result = app.consolidate([f, dict(f, lines=[2])], rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["lines"], [1, 2])


if __name__ == "__main__":
    unittest.main()
