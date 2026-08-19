###############################################################################################################################
# Funciones para la cabera de los reportes
###############################################################################################################################

# Retorna la cantidad de conexiones
def count_registros(hashmap):
    total = 0
    for value in hashmap.values():
        total += len(value)
    return total

# Retorna la cantidad de conexiones fallidas
def count_registros_failed(hashmap):
    total = 0
    for value in hashmap.values():
        if value["result"] == "failed":
            total += len(value["details"])
    return total

###############################################################################################################################
# Funciones para detectores
###############################################################################################################################

# Identifica si una dirección IP pertenece a una red privada.
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


# Filtra las IPs públicas.
# Input: hashmap devueltos por parser.py
# Output: hashmap filtrado
def public_ips(events):

    for event in events:
        attempts[event.ip_address] += 1

    public_ips_result = {
        ip: count for ip, count in attempts.items() if not _is_private_ip(ip)
    }

    return _build_count_alerts(public_ips_result, "public_ips", "ip_address", "attempts")

'''
Alerta Media: Más de 10 fallos de IP X en 1 minuto.
Alerta Crítica: Más de 10 fallos de IP X seguidos de 1 acceso exitoso de IP X.
Alerta de Anomalía: Acceso exitoso del usuario Y desde un país o rango horario no habitual.
'''
# Calcula la severidad de una alerta según la cantidad de intentos observados.
def _severity_from_attempts(attempts):
    if attempts >= 5:
        return "high"
    if attempts >= 3:
        return "medium"
    return "low"


# Construye una alerta usando un helper común para todos los detectores.
def _build_alert_from_record(record, detector, message, severity, attempts, **overrides):
    if isinstance(record, dict):
        source = dict(record)
    else:
        source = vars(record).copy()

    payload = {
        "timestamp": overrides.get("timestamp", source.get("timestamp")),
        "hour": overrides.get("hour", source.get("hour")),
        "severity": severity,
        "detector": detector,
        "message": message,
        "user_id": overrides.get("user_id", source.get("user_ids", source.get("user_id", []))),
        "ip_address": overrides.get("ip_address", source.get("ip_address")),
        "attempts": attempts if attempts is not None else source.get("attempts", 0),
    }

    for key, value in source.items():
        if key not in payload:
            payload[key] = value

    payload.update({key: value for key, value in overrides.items() if key not in payload})
    return build_alert(**payload)


# Genera alertas de conteo para los detectores que agregan por una clave.
def _build_count_alerts(records, detector, key_name, value_name, extra_fields=None):
    alerts = []
    for key, value in records.items():
        payload = {
            "timestamp": None,
            "hour": None,
            "user_id": [],
            "ip_address": key if key_name == "ip_address" else None,
            "attempts": value,
        }
        if extra_fields:
            payload.update(extra_fields(key, value))

        message = f"{value} eventos detectados para {key_name} {key}"
        alerts.append(
            _build_alert_from_record(
                payload,
                detector,
                message=message,
                severity=_severity_from_attempts(value),
                attempts=value,
                timestamp=None,
                hour=None,
                user_id=payload.get("user_id", []),
                ip_address=payload.get("ip_address"),
            )
        )
    return alerts

# Convierte un evento o un diccionario en una alerta con formato homogéneo.
def event_to_alert(event, detector="attempts_for_ip"):
    if isinstance(event, dict):
        ip_address = event.get("ip_address")
        user_ids = event.get("user_ids", [])
        attempts = event.get("attempts", 0)
        timestamp = event.get("timestamp")
        hour = event.get("hour")
    else:
        ip_address = getattr(event, "ip_address", None)
        user_ids = getattr(event, "user_id", [])
        attempts = getattr(event, "attempts", 0)
        timestamp = getattr(event, "timestamp", None)
        hour = getattr(event, "hour", None)

    if isinstance(user_ids, list):
        normalized_user_ids = sorted(user_ids)
    elif user_ids:
        normalized_user_ids = [user_ids]
    else:
        normalized_user_ids = []

    severity = _severity_from_attempts(attempts)
    message = (
        f"{attempts} intentos detectados para la IP {ip_address} "
        f"desde los usuarios: {', '.join(normalized_user_ids) if normalized_user_ids else 'sin usuarios'}"
    )

    return _build_alert_from_record(
        event,
        detector,
        message=message,
        severity=severity,
        attempts=attempts,
        timestamp=timestamp,
        hour=hour,
        user_id=normalized_user_ids,
        ip_address=ip_address,
    )