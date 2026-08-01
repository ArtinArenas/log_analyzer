import re

from models import Event


def parse_log():
    records = []

    pattern = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2})\s+"
        r"(?P<hour>\d{6})\s+"
        r"(?P<action>\w+)\s+"
        r"user=(?P<user_id>\w+)\s+"
        r"ip=(?P<ip_address>\d+\.\d+\.\d+\.\d+)"
    )

    with open("activity.log", "r", encoding="utf-8") as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                records.append(
                    Event(
                        match.group("timestamp"),
                        match.group("hour"),
                        match.group("action"),
                        match.group("user_id"),
                        match.group("ip_address"),
                        0,
                    )
                )

    return records