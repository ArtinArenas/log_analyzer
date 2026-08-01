
# Lógica para la detección de eventos

from collections import defaultdict

from models import Alert


def _severity_from_attempts(attempts):
    if attempts >= 5:
        return "high"
    if attempts >= 3:
        return "medium"
    return "low"


def event_to_alert(event, detector="attempts_for_ip"):
    if isinstance(event, dict):
        ip_address = event.get("ip_address")
        user_ids = sorted(event.get("user_ids", []))
        attempts = event.get("attempts", 0)
        timestamp = event.get("timestamp")
        hour = event.get("hour")
    else:
        ip_address = getattr(event, "ip_address", None)
        user_ids = getattr(event, "user_id", [])
        attempts = getattr(event, "attempts", 0)
        timestamp = getattr(event, "timestamp", None)
        hour = getattr(event, "hour", None)

    severity = _severity_from_attempts(attempts)
    message = (
        f"{attempts} intentos detectados para la IP {ip_address} "
        f"desde los usuarios: {', '.join(user_ids) if user_ids else 'sin usuarios'}"
    )

    return Alert(
        timestamp,
        hour,
        severity,
        detector,
        message,
        user_ids,
        ip_address,
        attempts,
    )


# Detectar intentos de login por IP
def attempts_for_ip(events):
    attempts = {}

    for event in events:
        entry = attempts.setdefault(
            event.ip_address,
            {
                "ip_address": event.ip_address,
                "timestamp": None,
                "hour": None,
                "attempts": 0,
                "user_ids": set(),
            },
        )

        entry["attempts"] += 1
        entry["user_ids"].add(event.user_id[0] if isinstance(event.user_id, list) else event.user_id)

        if entry["timestamp"] is None:
            entry["timestamp"] = event.timestamp
        if entry["hour"] is None:
            entry["hour"] = event.hour

    alerts = []
    for record in attempts.values():
        if record["attempts"] <= 1:
            continue

        record["timestamp"] = None
        record["hour"] = None
        record["user_ids"] = sorted(record["user_ids"])
        alerts.append(event_to_alert(record, detector="attempts_for_ip"))

    return alerts


# Detectar intentos fallidos por IP
def failed_attempts_for_ip(events):
    failed = defaultdict(int)
    for event in events:
        if event.action == "LOGIN_FAILED":
            failed[event.ip_address] += 1

    return dict(failed)


# Detectar fuerza bruta por IP
def brute_force_for_ip(events, threshold=5):
    failed = failed_attempts_for_ip(events)
    brute_force = {ip: count for ip, count in failed.items() if count >= threshold}

    return brute_force


# Detectar horarios de actividad sospechosa
def suspicious_activity_by_hour(events, hour_inferior, hour_superior):
    counts = defaultdict(int)
    for event in events:
        counts[event.hour] += 1

    suspicious_hours = {
        hour: count for hour, count in counts.items() if hour_inferior <= hour <= hour_superior
    }

    return suspicious_hours


# Detectar IPs públicas
def _is_private_ip(ip_address):
    try:
        octets = [int(part) for part in ip_address.split(".")]
    except ValueError:
        return False

    if len(octets) != 4 or any(part < 0 or part > 255 for part in octets):
        return False

    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if ip_address in {"127.0.0.1", "0.0.0.0"}:
        return True

    return False


def public_ips(events):
    failed = defaultdict(int)
    for event in events:
        if event.action == "LOGIN_FAILED":
            failed[event.ip_address] += 1

    public_ips_result = {
        ip: count for ip, count in failed.items() if not _is_private_ip(ip)
    }

    return public_ips_result


# Alias para compatibilidad
EventToAlert = event_to_alert
attemptsForIp = attempts_for_ip
failedAttemptsForIp = failed_attempts_for_ip
bruteForceForIp = brute_force_for_ip
suspiciousActivityByHour = suspicious_activity_by_hour
publicIps = public_ips
