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
            Event("2026-07-20", "081532", "LOGIN_FAILED", "admin", "192.168.1.15", 0),
            Event("2026-07-20", "081533", "LOGIN_FAILED", "admin", "192.168.1.15", 0),
            Event("2026-07-20", "081534", "LOGIN_FAILED", "root", "192.168.1.15", 0),
            Event("2026-07-20", "081535", "LOGIN_FAILED", "root", "192.168.1.16", 0),
            Event("2026-07-20", "081536", "LOGIN_SUCCESS", "root", "192.168.1.16", 0),
            Event("2026-07-20", "081537", "LOGIN_FAILED", "root", "8.8.8.8", 0),
        ]

    def test_attempts_for_ip_aggregates_users_and_severity(self):
        alerts = attempts_for_ip(self.events)
        self.assertEqual(len(alerts), 2)

        by_ip = {alert.ip_address: alert for alert in alerts}
        alert = by_ip["192.168.1.15"]
        self.assertEqual(alert.attempts, 3)
        self.assertEqual(set(alert.user_id), {"admin", "root"})
        self.assertEqual(alert.severity, "medium")

    def test_failed_attempts_for_ip_counts_only_failed_events(self):
        result = failed_attempts_for_ip(self.events)
        by_ip = {item.ip_address: item for item in result}
        self.assertEqual(by_ip["192.168.1.15"].attempts, 3)
        self.assertEqual(by_ip["192.168.1.16"].attempts, 1)

    def test_brute_force_for_ip_uses_threshold(self):
        result = brute_force_for_ip(self.events, threshold=3)
        by_ip = {item.ip_address: item for item in result}
        self.assertEqual(by_ip["192.168.1.15"].attempts, 3)
        self.assertNotIn("192.168.1.16", by_ip)

    def test_suspicious_activity_by_hour_filters_range(self):
        result = suspicious_activity_by_hour(self.events, "081532", "081535")
        by_hour = {item.hour: item for item in result}
        self.assertEqual(by_hour["081532"].attempts, 1)
        self.assertEqual(by_hour["081535"].attempts, 1)
        self.assertNotIn("081536", by_hour)

    def test_public_ips_filters_out_private_addresses(self):
        result = public_ips(self.events)
        by_ip = {item.ip_address: item for item in result}
        self.assertEqual(by_ip["8.8.8.8"].attempts, 1)
        self.assertNotIn("192.168.1.15", by_ip)
        self.assertNotIn("192.168.1.16", by_ip)


if __name__ == "__main__":
    unittest.main()
