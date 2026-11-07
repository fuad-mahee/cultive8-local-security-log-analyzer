import unittest
from unittest.mock import patch, Mock
import local_runtime


class RuntimeTests(unittest.TestCase):
    def test_recycle_after_six_calls(self):
        r = local_runtime.LocalRuntime()
        r.process = Mock(pid=123)
        r.process.poll.return_value = None
        r.calls = 6
        with patch.object(
            local_runtime, "resident_bytes", return_value=500_000_000
        ), patch.object(r, "stop") as stop, patch.object(r, "start") as start:
            r.ensure_ready()
            stop.assert_called_once()
            start.assert_called_once()
            self.assertEqual(r.restarts, 1)

    def test_memory_guard_recycles_before_next_call(self):
        r = local_runtime.LocalRuntime()
        r.process = Mock(pid=123)
        r.process.poll.return_value = None
        with patch.object(
            local_runtime, "resident_bytes", side_effect=[2_600_000_000, 40_000_000]
        ), patch.object(r, "stop") as stop, patch.object(r, "start") as start:
            r.ensure_ready()
            stop.assert_called_once()
            self.assertEqual(r.max_observed, 2_640_000_000)

    def test_post_call_guard_stops_only_owned_child(self):
        r = local_runtime.LocalRuntime()
        r.process = Mock(pid=123)
        with patch.object(
            local_runtime, "resident_bytes", return_value=1_700_000_000
        ), patch.object(r, "stop") as stop:
            r.completed()
            stop.assert_called_once()
            self.assertEqual(r.calls, 1)
