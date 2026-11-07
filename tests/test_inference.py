import tempfile, unittest, json
from pathlib import Path
from unittest.mock import patch
import app


class InferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = patch.object(app, "DATA", Path(self.tmp.name))
        self.data.start()
        with app.db() as c:
            c.execute(
                "CREATE TABLE calls(job TEXT,key TEXT,response TEXT,tokens INTEGER,seconds REAL,actual_prompt INTEGER,output_tokens INTEGER,PRIMARY KEY(job,key))"
            )
        self.data_input = {
            "logs": [{"line": 1, "event": {"client_ip": "x", "path": "/.env"}}],
            "prior_facts": [],
        }
        self.finding = {
            "type": "Scanning",
            "severity": "Medium",
            "identity": "x",
            "lines": [1],
            "reason": "Sensitive path probed",
            "action": "Review requests",
            "outcome": "attempted",
        }

    def tearDown(self):
        self.data.stop()
        self.tmp.cleanup()

    def test_broken_json_retry_and_checkpoint_reuse(self):
        responses = [
            {"content": "{broken", "tokens_evaluated": 20, "tokens_predicted": 5},
            {
                "content": json.dumps({"findings": [self.finding]}),
                "tokens_evaluated": 20,
                "tokens_predicted": 40,
            },
        ]
        with patch.object(app, "prompt", return_value="prompt"), patch.object(
            app, "tokens", return_value=20
        ), patch.object(app, "post", side_effect=responses) as post, patch.object(
            app.time, "sleep"
        ):
            first = app.infer("j", "c", self.data_input, {1})
            second = app.infer("j", "c", self.data_input, {1})
            self.assertEqual(first, second)
            self.assertEqual(post.call_count, 2)

    def test_over_budget_never_calls_model(self):
        with patch.object(app, "prompt", return_value="large"), patch.object(
            app, "tokens", return_value=1500
        ), patch.object(app, "post") as post:
            with self.assertRaises(ValueError):
                app.infer("j", "c", self.data_input, {1})
            post.assert_not_called()

    def test_failure_keeps_completed_checkpoint(self):
        with app.db() as c:
            c.execute(
                "INSERT INTO calls(job,key,response,tokens,seconds) VALUES(?,?,?,?,?)",
                ("j", "previous", "[]", 10, 1),
            )
        with patch.object(app, "prompt", return_value="p"), patch.object(
            app, "tokens", return_value=20
        ), patch.object(
            app, "post", side_effect=TimeoutError("model timed out")
        ), patch.object(
            app.time, "sleep"
        ):
            with self.assertRaises(RuntimeError):
                app.infer("j", "new", self.data_input, {1})
        with app.db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM calls").fetchone()[0], 1)

    def test_reviewer_can_reject_without_forced_type(self):
        data = dict(self.data_input, candidate={"type": "Scanning", "identity": "x"})
        with patch.object(app, "prompt", return_value="review"), patch.object(
            app, "tokens", return_value=20
        ), patch.object(
            app,
            "post",
            return_value={
                "content": '{"findings":[]}',
                "tokens_evaluated": 20,
                "tokens_predicted": 5,
            },
        ) as post:
            self.assertEqual(app.infer("j", "review", data, {1}), [])
            schema = post.call_args.args[1]["json_schema"]["properties"]["findings"]
            self.assertEqual(schema["minItems"], 0)
            self.assertGreater(len(schema["items"]["properties"]["type"]["enum"]), 1)
