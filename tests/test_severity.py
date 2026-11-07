import unittest
import app


class SeverityTests(unittest.TestCase):
    def test_compromise_priority_floor_preserves_model_severity(self):
        f = {
            "type": "Suspected account compromise",
            "severity": "Medium",
            "identity": "x",
            "lines": [1],
            "reason": "Repeated failures then success",
            "action": "Investigate",
            "outcome": "suspected compromise",
        }
        result = app.consolidate([f], {1: {"event": {}, "source_lines": [1]}})[0]
        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["model_severity"], "Medium")
        self.assertEqual(f["severity"], "Medium")
