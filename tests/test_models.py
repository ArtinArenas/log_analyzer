import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))

from models import classify_event, normalize_action, normalize_outcome


class ModelTests(unittest.TestCase):
    def test_normalize_action_and_outcome_from_ssh_result(self):
        self.assertEqual(normalize_action("LOGIN", "Accepted", "publickey"), "LOGIN_SUCCESS")
        self.assertEqual(normalize_action("LOGIN", "Failed", "password"), "LOGIN_FAILED")
        self.assertEqual(normalize_outcome("Accepted", "LOGIN"), "success")
        self.assertEqual(normalize_outcome("Failed", "LOGIN"), "failure")

    def test_normalize_unknown_values(self):
        self.assertEqual(normalize_action("other"), "LOGIN")
        self.assertEqual(normalize_outcome("other", "other"), "unknown")

    def test_classify_event_prefers_existing_outcome(self):
        event = SimpleNamespace(outcome="failure", action="LOGIN_SUCCESS", result="Accepted")

        self.assertEqual(classify_event(event), "failure")

    def test_classify_event_derives_missing_outcome(self):
        event = SimpleNamespace(action="LOGIN_FAILED", result=None)

        self.assertEqual(classify_event(event), "failure")


if __name__ == "__main__":
    unittest.main()