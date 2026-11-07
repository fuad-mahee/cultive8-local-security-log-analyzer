import unittest
from unittest.mock import patch
import app


class BudgetTests(unittest.TestCase):
    def test_every_chunk_fits_target(self):
        rows = [
            {"line": i, "source_lines": [i], "event": {"message": "x" * 220}}
            for i in range(1, 30)
        ]
        with patch.object(app, "prompt", side_effect=lambda d: str(d)), patch.object(
            app, "tokens", side_effect=lambda t: len(t) // 3
        ):
            batches = list(app.chunks(rows))
            self.assertEqual(sum(len(b) for b in batches), 29)
            for batch in batches:
                self.assertLessEqual(
                    app.tokens(app.prompt({"logs": batch, "prior_facts": []})), 1250
                )

    def test_oversized_entry_preserves_line(self):
        row = {"line": 9, "source_lines": [9], "event": {"message": "x" * 12000}}
        with patch.object(app, "prompt", side_effect=lambda d: str(d)), patch.object(
            app, "tokens", side_effect=lambda t: len(t) // 3
        ):
            batches = list(app.chunks([row]))
            self.assertGreater(len(batches), 1)
            self.assertTrue(all(b[0]["line"] == 9 for b in batches))

    def test_incomplete_json_rejected(self):
        with self.assertRaises(ValueError):
            app.validate({"findings": [{}]}, {1})
