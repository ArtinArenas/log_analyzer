from datetime import datetime, timedelta
from ipaddress import ip_address
from types import SimpleNamespace

from config import (
    DEFAULT_HOUR_INFERIOR,
    DEFAULT_HOUR_SUPERIOR,
    PERSISTENT_BRUTE_FORCE_THRESHOLD,
    POSSIBLE_COMPROMISE_THRESHOLD,
    RAPID_BRUTE_FORCE_THRESHOLD,
    RAPID_BRUTE_FORCE_WINDOW_MINUTES,
    SPRAYING_USER_THRESHOLD,
)
from models import classify_event


def _event_user(event):
    if event is None:
        return None
    user = getattr(event, "user", None)
    if user is not None:
        return user
    user_id = getattr(event, "user_id", None)
    if isinstance(user_id, list):
        return user_id[0] if user_id else None
    if isinstance(user_id, tuple):
        return user_id[0] if user_id else None
    return user_id


def _group_by_ip(events):
    if isinstance(events, dict):
        return events
    grouped = {}
    for event in events:
        ip_value = getattr(event, "ip_address", None)
        if ip_value is None:
            continue
        grouped.setdefault(ip_value, []).append(event)
    return grouped


def _is_private_ip(ip_value):
    try:
        parsed = ip_address(str(ip_value))
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _to_hour_value(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace(":", "")
    return value


def attempts_for_ip(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        attempts = len(records)
        users = sorted({user for user in (_event_user(record) for record in records) if user})
        severity = "high" if attempts >= 5 else "medium" if attempts >= 3 else "low"
        results.append(SimpleNamespace(ip_address=ip_value, attempts=attempts, user_id=users, severity=severity))
    return results


def failed_attempts_for_ip(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        failed_records = [record for record in records if classify_event(record) == "failure"]
        if not failed_records:
            continue
        users = sorted({user for user in (_event_user(record) for record in failed_records) if user})
        results.append(SimpleNamespace(ip_address=ip_value, attempts=len(failed_records), user_id=users, severity="medium" if len(failed_records) >= 3 else "low"))
    return results


def suspicious_activity_by_hour(events, hour_inferior=None, hour_superior=None):
    if hour_inferior is None:
        hour_inferior = DEFAULT_HOUR_INFERIOR.strftime("%H%M%S")
    elif hasattr(hour_inferior, "strftime"):
        hour_inferior = hour_inferior.strftime("%H%M%S")

    if hour_superior is None:
        hour_superior = DEFAULT_HOUR_SUPERIOR.strftime("%H%M%S")
    elif hasattr(hour_superior, "strftime"):
        hour_superior = hour_superior.strftime("%H%M%S")

    counts = {}
    for record in events if not isinstance(events, dict) else [item for group in events.values() for item in group]:
        hour_value = _to_hour_value(getattr(record, "hour", None))
        if hour_value is None:
            timestamp = getattr(record, "timestamp", None)
            if isinstance(timestamp, str) and "T" in timestamp:
                hour_value = timestamp[11:19].replace(":", "")
            elif isinstance(timestamp, str) and len(timestamp) >= 19:
                hour_value = timestamp[11:19].replace(":", "")
        if hour_value and hour_inferior <= hour_value <= hour_superior:
            counts[hour_value] = counts.get(hour_value, 0) + 1
    return [SimpleNamespace(hour=hour, attempts=count) for hour, count in sorted(counts.items())]


def brute_force_for_ip(events, threshold=RAPID_BRUTE_FORCE_THRESHOLD):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        failed = [record for record in records if classify_event(record) == "failure"]
        if len(failed) >= threshold:
            results.append(SimpleNamespace(ip_address=ip_value, attempts=len(failed)))
    return results


def public_ips(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        if _is_private_ip(ip_value):
            continue
        results.append(SimpleNamespace(ip_address=ip_value, attempts=len(records)))
    return results


def detect_rapid_brute_force(attempts):
    failed_attempts = [attempt for attempt in attempts if classify_event(attempt) == "failure"]
    if len(failed_attempts) < RAPID_BRUTE_FORCE_THRESHOLD:
        return False

    for index in range(len(failed_attempts) - RAPID_BRUTE_FORCE_THRESHOLD + 1):
        current = failed_attempts[index]
        window_end = failed_attempts[index + RAPID_BRUTE_FORCE_THRESHOLD - 1]
        current_ts = datetime.fromisoformat(current.timestamp) if isinstance(current.timestamp, str) else current.timestamp
        end_ts = datetime.fromisoformat(window_end.timestamp) if isinstance(window_end.timestamp, str) else window_end.timestamp
        if end_ts - current_ts <= timedelta(minutes=RAPID_BRUTE_FORCE_WINDOW_MINUTES):
            return True
    return False


def detect_persistent_brute_force(attempts):
    consecutive_failures = 0
    for attempt in attempts:
        if classify_event(attempt) == "failure":
            consecutive_failures += 1
            if consecutive_failures >= PERSISTENT_BRUTE_FORCE_THRESHOLD:
                return True
        else:
            consecutive_failures = 0
    return False


def detect_possible_compromise(attempts):
    by_user = {}
    for attempt in attempts:
        user = _event_user(attempt)
        if user is None:
            continue
        current = by_user.setdefault(user, {"failed": 0, "compromised": False})
        if classify_event(attempt) == "failure":
            current["failed"] += 1
        elif classify_event(attempt) == "success":
            if current["failed"] >= POSSIBLE_COMPROMISE_THRESHOLD:
                current["compromised"] = True
            else:
                current["failed"] = 0
    return [
        {"user": user, "failedAttempts": values["failed"], "compromise": values["compromised"]}
        for user, values in by_user.items()
        if values["compromised"]
    ]


def detect_spraying_brute_force(attempts):
    users = {
        _event_user(attempt)
        for attempt in attempts
        if classify_event(attempt) == "failure" and _event_user(attempt) is not None
    }
    return len(users) >= SPRAYING_USER_THRESHOLD


def detect_brute_force_by_ip(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        results.append(SimpleNamespace(
            ip_address=ip_value,
            rapid=detect_rapid_brute_force(records),
            persistent=detect_persistent_brute_force(records),
            compromise=detect_possible_compromise(records),
            spraying=detect_spraying_brute_force(records),
        ))
    return results


def detect_distributed_brute_force(events):
    by_user = {}
    for event in events:
        user = _event_user(event)
        if user is None:
            continue
        if classify_event(event) == "failure":
            by_user.setdefault(user, set()).add(event.ip_address)
    return [
        {"user": user, "ips": sorted(ip_set), "attempts": len(ip_set)}
        for user, ip_set in by_user.items()
        if len(ip_set) > 1
    ]


def _successful_events(events):
    return [event for event in events if classify_event(event) == "success"]


def _events_in_window(events, window_minutes=5):
    ordered = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event.timestamp) if isinstance(event.timestamp, str) else event.timestamp,
    )
    for index, event in enumerate(ordered):
        window = [event]
        for other in ordered[index + 1:]:
            current_ts = datetime.fromisoformat(event.timestamp) if isinstance(event.timestamp, str) else event.timestamp
            other_ts = datetime.fromisoformat(other.timestamp) if isinstance(other.timestamp, str) else other.timestamp
            if other_ts - current_ts > timedelta(minutes=window_minutes):
                break
            window.append(other)
        yield window


def multi_connections(events, window_minutes=5):
    successful = _successful_events(events)
    by_user = {}
    for event in successful:
        user = _event_user(event)
        if user is None:
            continue
        by_user.setdefault(user, set()).add(event.ip_address)
    return [
        {"user": user, "ips": sorted(ip_set), "attempts": len(ip_set)}
        for user, ip_set in by_user.items()
        if len(ip_set) > 1
    ]


def geo_connections(events, window_minutes=5):
    return multi_connections(events, window_minutes=window_minutes)


def out_horary_connections(events, work_start=8, work_end=18):
    alerts = []
    for event in events:
        if classify_event(event) != "success":
            continue
        hour_value = _to_hour_value(getattr(event, "hour", None))
        if hour_value is None:
            continue
        hour_int = int(hour_value[:2])
        if hour_int < work_start or hour_int >= work_end:
            alerts.append({
                "user": _event_user(event),
                "ip": event.ip_address,
                "hour": hour_value,
            })
    return alerts


def detect_anomalias(events, window_minutes=5, work_start=8, work_end=18):
    return {
        "multi_connections": multi_connections(events, window_minutes=window_minutes),
        "geo_connections": geo_connections(events, window_minutes=window_minutes),
        "out_horary_connections": out_horary_connections(events, work_start=work_start, work_end=work_end),
    }
