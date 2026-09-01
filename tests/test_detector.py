import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))

from detector import (
    attempts_for_ip,
    brute_force_for_ip,
    failed_attempts_for_ip,
    public_ips,
    suspicious_activity_by_hour,
)
from models import Event


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            Event("2026-07-20", "000100", "LOGIN_FAILED", "alice", "192.168.1.10", 1, outcome="failure"),
            Event("2026-07-20", "000101", "LOGIN_FAILED", "alice", "192.168.1.10", 1, outcome="failure"),
            Event("2026-07-20", "000102", "LOGIN_FAILED", "bob", "192.168.1.10", 1, outcome="failure"),
            Event("2026-07-20", "020000", "LOGIN_SUCCESS", "bob", "192.168.1.11", 1, outcome="success"),
            Event("2026-07-20", "020001", "LOGIN_FAILED", "charlie", "8.8.8.8", 1, outcome="failure"),
        ]

    def test_attempts_for_ip_aggregates_users_and_severity(self):
        alerts = attempts_for_ip(self.events)
        by_ip = {alert.ip_address: alert for alert in alerts}

        self.assertEqual(len(alerts), 3)
        self.assertEqual(by_ip["192.168.1.10"].attempts, 3)
        self.assertEqual(set(by_ip["192.168.1.10"].user_id), {"alice", "bob"})
        self.assertEqual(by_ip["192.168.1.10"].severity, "medium")

    def test_failed_attempts_for_ip_counts_only_failed_events(self):
        result = failed_attempts_for_ip(self.events)
        by_ip = {item.ip_address: item for item in result}

        self.assertEqual(by_ip["192.168.1.10"].attempts, 3)
        self.assertEqual(by_ip["8.8.8.8"].attempts, 1)

    def test_brute_force_for_ip_uses_threshold(self):
        result = brute_force_for_ip(self.events, threshold=3)
        by_ip = {item.ip_address: item for item in result}

        self.assertEqual(by_ip["192.168.1.10"].attempts, 3)
        self.assertNotIn("192.168.1.11", by_ip)

    def test_suspicious_activity_by_hour_filters_range(self):
        result = suspicious_activity_by_hour(self.events, "000100", "000102")
        by_hour = {item.hour: item for item in result}

        self.assertEqual(by_hour["000100"].attempts, 1)
        self.assertEqual(by_hour["000102"].attempts, 1)
        self.assertNotIn("020000", by_hour)

    def test_public_ips_filters_out_private_addresses(self):
        result = public_ips(self.events)
        by_ip = {item.ip_address: item for item in result}

        self.assertEqual(by_ip["8.8.8.8"].attempts, 1)
        self.assertNotIn("192.168.1.10", by_ip)
        self.assertNotIn("192.168.1.11", by_ip)


if __name__ == "__main__":
    unittest.main()
