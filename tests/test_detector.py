import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))

from detector import (
    attempts_for_ip,
    brute_force_for_ip,
    failed_attempts_for_ip,
    geo_connections,
    multi_connections,
    out_horary_connections,
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
        by_ip = {item.ip_address: item for item in result}

        self.assertEqual(by_ip["192.168.1.10"].attempts, 3)
        self.assertEqual(set(by_ip["192.168.1.10"].user_id), {"alice", "bob"})
        self.assertEqual(by_ip["192.168.1.10"].severity, "medium")
        self.assertNotIn("192.168.1.11", by_ip)

    def test_public_ips_filters_out_private_addresses(self):
        result = public_ips(self.events)
        by_ip = {item.ip_address: item for item in result}

        self.assertEqual(by_ip["8.8.8.8"].attempts, 1)
        self.assertNotIn("192.168.1.10", by_ip)
        self.assertNotIn("192.168.1.11", by_ip)

    def test_multi_connections_detects_all_users_and_merges_overlapping_windows(self):
        events = [
            Event("2026-07-20T10:00:00", "100000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T10:04:00", "100400", "LOGIN_SUCCESS", "alice", "10.0.0.2", 1, outcome="success"),
            Event("2026-07-20T10:20:00", "102000", "LOGIN_SUCCESS", "bob", "10.0.0.3", 1, outcome="success"),
            Event("2026-07-20T10:24:00", "102400", "LOGIN_SUCCESS", "bob", "10.0.0.4", 1, outcome="success"),
            Event("2026-07-20T10:04:30", "100430", "LOGIN_FAILED", "alice", "10.0.0.9", 1, outcome="failure"),
        ]

        result = multi_connections(events, window_minutes=5)

        self.assertEqual(len(result), 2)
        by_user = {alert["user"]: alert for alert in result}
        self.assertEqual(by_user["alice"]["ips"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(by_user["alice"]["numberOfIPs"], 2)
        self.assertEqual(by_user["bob"]["ips"], ["10.0.0.3", "10.0.0.4"])

    def test_geo_connections_detects_different_countries(self):
        events = [
            Event("2026-07-20T10:00:00", "100000", "LOGIN_SUCCESS", "alice", "8.8.8.8", 1, outcome="success"),
            Event("2026-07-20T10:04:00", "100400", "LOGIN_SUCCESS", "alice", "1.1.1.1", 1, outcome="success"),
            Event("2026-07-20T10:20:00", "102000", "LOGIN_SUCCESS", "bob", "8.8.4.4", 1, outcome="success"),
            Event("2026-07-20T10:24:00", "102400", "LOGIN_SUCCESS", "bob", "8.8.8.8", 1, outcome="success"),
        ]

        class FakeReader:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def get(self, ip):
                country = "US" if ip.startswith("8.8.") else "AU"
                return {"country_code": country}

        with patch("detector.maxminddb.open_database", return_value=FakeReader()) as reader:
            result = geo_connections(events, window_minutes=5)

        self.assertEqual(reader.call_count, 1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")
        self.assertEqual(result[0]["countries"], ["AU", "US"])
        self.assertEqual(result[0]["numberOfCountries"], 2)

    def test_out_horary_connections_detects_success_outside_personal_range(self):
        events = [
            Event("2026-07-20T10:00:00", "100000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T10:15:00", "100000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T10:00:00", "100000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T10:30:00", "100000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T11:00:00", "110000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T11:15:00", "110000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T11:30:00", "110000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T20:00:00", "200000", "LOGIN_SUCCESS", "alice", "10.0.0.1", 1, outcome="success"),
            Event("2026-07-20T20:05:00", "200500", "LOGIN_FAILED", "alice", "10.0.0.1", 1, outcome="failure"),
        ]

        result = out_horary_connections(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")
        self.assertEqual(result[0]["hour"], "200000")
        self.assertGreater(result[0]["lower_bound"], 9 * 60)
        self.assertLess(result[0]["upper_bound"], 20 * 60)


if __name__ == "__main__":
    unittest.main()
