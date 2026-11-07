import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, Mock
import app


class PipelineTests(unittest.TestCase):
    def evaluate(self, reject):
        with tempfile.TemporaryDirectory() as tmp, patch.object(app, "DATA", Path(tmp)):
            with app.db() as c:
                c.execute(
                    "CREATE TABLE jobs(id TEXT PRIMARY KEY,state TEXT,detail TEXT,total INTEGER,done INTEGER,report TEXT)"
                )
                c.execute(
                    "CREATE TABLE calls(job TEXT,key TEXT,tokens INTEGER,seconds REAL,actual_prompt INTEGER,output_tokens INTEGER)"
                )
                c.execute("INSERT INTO jobs(id) VALUES(?)", ("j",))
            Path(tmp, "j.log").write_text(
                json.dumps(
                    {
                        "client_ip": "synthetic-source",
                        "host": "demo",
                        "message": "custom authorization signal",
                    }
                )
            )
            finding = {
                "type": "SQL injection",
                "severity": "Medium",
                "identity": "synthetic-source",
                "lines": [1],
                "reason": "proposed",
                "action": "Investigate",
                "outcome": "unknown",
            }

            def inference(job, key, data, allowed):
                if key.startswith("chunk"):
                    return [finding]
                return (
                    []
                    if reject
                    else [
                        dict(
                            finding,
                            type="Unauthorized access",
                            reason="Reviewed evidence",
                        )
                    ]
                )

            with patch.object(
                app, "chunks", side_effect=lambda records, budget=1250: iter([records])
            ), patch.object(app, "prompt", return_value="p"), patch.object(
                app, "tokens", return_value=10
            ), patch.object(
                app, "infer", side_effect=inference
            ):
                app.run("j")
            with app.db() as c:
                r = dict(c.execute("SELECT * FROM jobs").fetchone())
            self.assertEqual(r["state"], "completed")
            return json.loads(r["report"])

    def test_model_only_discovery_is_reviewed_and_can_be_reclassified(self):
        r = self.evaluate(False)
        self.assertEqual(r["findings"][0]["type"], "Unauthorized access")
        self.assertEqual(r["findings"][0]["reason"], "Reviewed evidence")
        self.assertEqual(r["reviews"][0]["origin"], "model")

    def test_rejected_discovery_does_not_become_final_finding(self):
        r = self.evaluate(True)
        self.assertEqual(r["findings"], [])
        self.assertFalse(r["reviews"][0]["accepted"])

    def test_worker_is_reserved_before_thread_start(self):
        with patch.object(app, "update"), patch.object(app.threading, "Thread"):
            try:
                self.assertTrue(app.launch("one"))
                self.assertFalse(app.launch("two"))
            finally:
                if app.LOCK.locked():
                    app.LOCK.release()
