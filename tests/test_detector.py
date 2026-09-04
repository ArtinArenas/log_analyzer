import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))

from detector import (
    attempts_for_ip,
    detect_anomalias,
    detect_brute_force_by_ip,
    detect_distributed_brute_force,
    detect_persistent_brute_force,
    detect_possible_compromise,
    detect_rapid_brute_force,
    detect_spraying_brute_force,
    failed_attempts_for_ip,
    geo_connections,
    multi_connections,
    out_horary_connections,
    suspicious_activity_by_hour,
)
from models import Event
from utils import public_ips


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

        self.assertEqual(by_ip["8.8.8.8"].user_id, ["charlie"])
        self.assertNotIn("192.168.1.10", by_ip)
        self.assertNotIn("192.168.1.11", by_ip)

    def test_rapid_brute_force_requires_ten_failures_in_one_minute(self):
        events = [
            Event("2026-07-20T10:00:{:02d}".format(index), "100000", "LOGIN_FAILED", "alice", "8.8.8.8", 1, outcome="failure")
            for index in range(10)
        ]

        self.assertTrue(detect_rapid_brute_force(events))
        self.assertFalse(detect_rapid_brute_force(events[:9]))

    def test_persistent_brute_force_requires_consecutive_failures(self):
        events = [
            Event("2026-07-20", "000000", "LOGIN_FAILED", "alice", "8.8.8.8", 1, outcome="failure")
            for _ in range(30)
        ]

        self.assertTrue(detect_persistent_brute_force(events))
        self.assertFalse(detect_persistent_brute_force(events[:29]))

    def test_possible_compromise_requires_failures_before_success(self):
        events = [
            Event("2026-07-20", "000000", "LOGIN_FAILED", "alice", "8.8.8.8", 1, outcome="failure")
            for _ in range(10)
        ]
        events.append(Event("2026-07-20", "000001", "LOGIN_SUCCESS", "alice", "8.8.8.8", 1, outcome="success"))

        self.assertEqual(detect_possible_compromise(events), [{
            "user": "alice",
            "failedAttempts": 10,
            "compromise": True,
        }])

    def test_spraying_requires_three_failed_users(self):
        events = [
            Event("2026-07-20", "000000", "LOGIN_FAILED", user, "8.8.8.8", 1, outcome="failure")
            for user in ("alice", "bob", "charlie")
        ]

        self.assertTrue(detect_spraying_brute_force(events))
        self.assertFalse(detect_spraying_brute_force(events[:2]))

    def test_distributed_brute_force_requires_multiple_ips_for_user(self):
        events = [
            Event("2026-07-20", "000000", "LOGIN_FAILED", "alice", "8.8.8.8", 1, outcome="failure"),
            Event("2026-07-20", "000001", "LOGIN_FAILED", "alice", "1.1.1.1", 1, outcome="failure"),
        ]

        self.assertEqual(detect_distributed_brute_force(events), [{
            "user": "alice",
            "ips": ["1.1.1.1", "8.8.8.8"],
            "numberOfIPs": 2,
        }])

    def test_detect_brute_force_by_ip_reports_triggered_ip(self):
        events = [
            Event("2026-07-20T10:00:{:02d}".format(index), "100000", "LOGIN_FAILED", "alice", "8.8.8.8", 1, outcome="failure")
            for index in range(10)
        ]

        result = detect_brute_force_by_ip(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].ip_address, "8.8.8.8")
        self.assertTrue(result[0].rapid)

    def test_detect_anomalias_returns_all_analysis_groups(self):
        with patch("detector.geo_connections", return_value=[]):
            result = detect_anomalias([])

        self.assertEqual(set(result), {"multi_connections", "geo_connections", "out_horary_connections"})
        self.assertEqual(result["multi_connections"], [])
        self.assertEqual(result["geo_connections"], [])
        self.assertEqual(result["out_horary_connections"], [])

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

        database = Mock(return_value=FakeReader())
        with patch("detector.maxminddb", SimpleNamespace(open_database=database), create=True):
            result = geo_connections(events, window_minutes=5)

        self.assertEqual(database.call_count, 1)
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
