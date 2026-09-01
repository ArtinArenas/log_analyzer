import re
from datetime import datetime

from models import Event, normalize_action, normalize_outcome

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


def example_parser(path="activity.log"):
    events = []
    pattern = re.compile(
        r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})\s+"
        r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})\s+"
        r"(?P<action>LOGIN(?:_(?:SUCCESS|FAILED))?)\s+"
        r"user=(?P<user_id>\w+)\s+"
        r"ip=(?P<ip_address>\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(pattern, line)
                if not match:
                    continue

                raw_action = match.group("action")
                raw_result = "success" if "SUCCESS" in raw_action.upper() else "failure" if "FAILED" in raw_action.upper() else "unknown"
                action = normalize_action(raw_action, raw_result)
                outcome = normalize_outcome(raw_result, raw_action)
                date_value = datetime(
                    year=int(match.group("year")),
                    month=int(match.group("month")),
                    day=int(match.group("day")),
                    hour=int(match.group("hour")),
                    minute=int(match.group("minute")),
                    second=int(match.group("second")),
                )
                events.append(
                    Event(
                        timestamp=date_value.date().isoformat(),
                        hour=f"{match.group('hour')}{match.group('minute')}{match.group('second')}",
                        action=action,
                        user_id=[match.group("user_id")],
                        ip_address=match.group("ip_address"),
                        attempts=1,
                        source="example",
                        result=raw_result,
                        method=None,
                        port=None,
                        raw=line.strip(),
                        outcome=outcome,
                    )
                )
    except FileNotFoundError:
        return []
    return events


def openSsh_parser(path="log_ssh.log"):
    events = []
    pattern = re.compile(
        r"(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"(?P<result>Accepted|Failed)\s+"
        r"(?P<method>password|publickey)\s+for\s+"
        r"(?:(?:invalid user)\s+)?"
        r"(?P<user_id>\S+)\s+"
        r"from\s+(?P<ip_address>\d+\.\d+\.\d+\.\d+)\s+"
        r"port\s+(?P<port>\d+)"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(pattern, line)
                if not match:
                    continue
                raw_result = match.group("result")
                raw_method = match.group("method")
                outcome = "success" if raw_result == "Accepted" else "failure"
                action = normalize_action("LOGIN", raw_result, raw_method)
                date_object = datetime(
                    year=datetime.now().year,
                    month=MONTHS.get(match.group("month").lower()),
                    day=int(match.group("day")),
                    hour=int(match.group("hour")),
                    minute=int(match.group("minute")),
                    second=int(match.group("second")),
                )
                events.append(
                    Event(
                        timestamp=date_object.date().isoformat(),
                        hour=f"{match.group('hour')}{match.group('minute')}{match.group('second')}",
                        action=action,
                        user_id=[match.group("user_id")],
                        ip_address=match.group("ip_address"),
                        attempts=1,
                        source="openssh",
                        result=raw_result,
                        method=raw_method,
                        port=int(match.group("port")),
                        raw=line.strip(),
                        outcome=outcome,
                    )
                )
    except FileNotFoundError:
        return []
    return events

