import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))

from parser import openSsh_parser, parse_log


class ParserTests(unittest.TestCase):
    def test_openSsh_parser_normalizes_fields(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("ago 01 14:16:02 debian sshd[2893]: Failed password for invalid user root from 192.168.1.37 port 40340 ssh2\n")
            temp_path = handle.name

        try:
            events = openSsh_parser(temp_path)
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertEqual(event.action, "LOGIN_FAILED")
            self.assertEqual(event.outcome, "failure")
            self.assertEqual(event.user_id, ["root"])
            self.assertEqual(event.ip_address, "192.168.1.37")
            self.assertEqual(event.hour, "141602")
            self.assertEqual(event.timestamp, f"{datetime.now().year}-08-01")
            self.assertEqual(event.source, "openssh")
            self.assertEqual(event.result, "Failed")
        finally:
            os.remove(temp_path)

    def test_parse_log_dispatches_to_open_ssh_parser(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("ago 01 14:18:27 debian sshd[2915]: Accepted publickey for juan from 192.168.1.37 port 38816 ssh2\n")
            temp_path = handle.name

        try:
            events = parse_log(temp_path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].action, "LOGIN_SUCCESS")
            self.assertEqual(events[0].outcome, "success")
            self.assertEqual(events[0].user_id, ["juan"])
            self.assertEqual(events[0].source, "openssh")
        finally:
            os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
