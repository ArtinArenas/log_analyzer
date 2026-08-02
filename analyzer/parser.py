import re
from datetime import datetime

from models import Event, build_event, normalize_action, normalize_outcome


MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "ago": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dic": 12,
}


def _read_log_content(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return ""


def parse_log(path="log_ssh.log"):
    content = _read_log_content(path)

    if "sshd[" in content or "Accepted" in content or "Failed" in content:
        return openSsh_parser(path)

    return example_parser(path)


#2026-07-20 081532 LOGIN_SUCCESS user=juan ip=192.168.1.15
#2026-07-20 081535 LOGIN_FAILED user=admin ip=192.168.1.15
def example_parser(path="activity.log"):
    records = []

    pattern = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2})\s+"
        r"(?P<hour>\d{6})\s+"
        r"(?P<action>\w+)\s+"
        r"user=(?P<user_id>\w+)\s+"
        r"ip=(?P<ip_address>\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    payload = {
                        "timestamp": match.group("timestamp"),
                        "hour": match.group("hour"),
                        "action": match.group("action"),
                        "user_id": match.group("user_id"),
                        "ip_address": match.group("ip_address"),
                        "attempts": 0,
                        "source": "example",
                        "raw": line.strip(),
                        "outcome": normalize_outcome(action=match.group("action")),
                    }
                    records.append(build_event(**payload))
    except FileNotFoundError:
        return []

    return records


#dic 10 22:17:27 debian sshd[16518]: Accepted password for paco from 192.168.1.47 port 49746 ssh2
#ago 01 14:16:02 debian sshd[2893]: Failed password for invalid user root from 192.168.1.37 port 40340 ssh2
#ago 01 14:18:27 debian sshd[2915]: Accepted publickey for juan from 192.168.1.37 port 38816 ssh2: ED25519 SHA256:w0z/sKhv9BpomD9XjxOL0kSokngs+qpAhpjYHpaX+KA

def openSsh_parser(path="log_ssh.log"):
    records = []

    pattern = re.compile(
        r"(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"(?P<result>Accepted|Failed)\s+"
        r"(?P<method>password|publickey)\s+for\s+"
        r"(?:(?:invalid user)\s+)?"
        r"(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"port\s+(?P<port>\d+)"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(pattern, line)
                if not match:
                    continue

                month = MONTHS.get(match.group("month").lower())
                if month is None:
                    month = 1
                day = int(match.group("day"))
                time_text = match.group("time")
                hour = time_text.replace(":", "")
                timestamp = f"{datetime.now().year:04d}-{month:02d}-{day:02d}"
                result = match.group("result")
                action = normalize_action(None, result=result, method=match.group("method"))

                payload = {
                    "timestamp": timestamp,
                    "hour": hour,
                    "action": action,
                    "user_id": match.group("user"),
                    "ip_address": match.group("ip"),
                    "attempts": 0,
                    "source": "openssh",
                    "result": result,
                    "method": match.group("method"),
                    "port": int(match.group("port")),
                    "raw": line.strip(),
                    "host": match.group("host"),
                    "pid": int(match.group("pid")),
                    "outcome": normalize_outcome(result=result, action=action),
                }
                records.append(build_event(**payload))
    except FileNotFoundError:
        return []

    return records

