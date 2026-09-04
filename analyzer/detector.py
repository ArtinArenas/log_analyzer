from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from models import classify_event
import maxminddb
from utils import (
    _event_user, 
    _group_by_ip,
    _is_private_ip, 
    _to_hour_value, 
    _hour_to_minutes, 
    _successful_events, 
    _events_in_window,
)
from config import (
    DEFAULT_HOUR_INFERIOR,
    DEFAULT_HOUR_SUPERIOR,
    PERSISTENT_BRUTE_FORCE_THRESHOLD,
    POSSIBLE_COMPROMISE_THRESHOLD,
    RAPID_BRUTE_FORCE_THRESHOLD,
    RAPID_BRUTE_FORCE_WINDOW_MINUTES,
    SPRAYING_USER_THRESHOLD,
)

# Detecta intentos de login por IP
def attempts_for_ip(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        attempts = len(records)
        users = sorted({user for user in (_event_user(record) for record in records) if user})
        severity = "high" if attempts >= 5 else "medium" if attempts >= 3 else "low"
        results.append(SimpleNamespace(ip_address=ip_value, attempts=attempts, user_id=users, severity=severity))
    return results

# Detecta intentos de login fallidos por IP
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

# Detecta intentos de login en un rango horario específico por IP
def suspicious_activity_by_hour(events, hour_inferior=None, hour_superior=None):
    if hour_inferior is None:
        hour_inferior = DEFAULT_HOUR_INFERIOR.strftime("%H%M%S")
    elif hasattr(hour_inferior, "strftime"):
        hour_inferior = hour_inferior.strftime("%H%M%S")

    if hour_superior is None:
        hour_superior = DEFAULT_HOUR_SUPERIOR.strftime("%H%M%S")
    elif hasattr(hour_superior, "strftime"):
        hour_superior = hour_superior.strftime("%H%M%S")

    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        matching_records = []
        for record in records:
            hour_value = _to_hour_value(getattr(record, "hour", None))
            if hour_value is None:
                timestamp = getattr(record, "timestamp", None)
                if isinstance(timestamp, str) and len(timestamp) >= 19:
                    hour_value = timestamp[11:19].replace(":", "")

            if hour_value is not None and hour_inferior <= hour_value <= hour_superior:
                matching_records.append(record)

        if matching_records:
            attempts = len(matching_records)
            users = sorted({
                user
                for user in (_event_user(record) for record in matching_records)
                if user
            })
            severity = "high" if attempts >= 5 else "medium" if attempts >= 3 else "low"
            results.append(SimpleNamespace(
                ip_address=ip_value,
                user_id=users,
                attempts=attempts,
                severity=severity,
            ))
    return results

# Detecta muchos intentos de login fallidos por IP en un corto período de tiempo
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

# Detecta muchos intentos de login fallidos por IP separados en tiempo para evitar ser detectados como un ataque de fuerza bruta rápido
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

# Detecta usuarios comprometidos por múltiples intentos fallidos de login seguidos de un intento exitoso
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

# Detecta intentos de login de una IP a multiples usuarios (ataque de fuerza bruta por spraying)
def detect_spraying_brute_force(attempts):
    users = {
        _event_user(attempt)
        for attempt in attempts
        if classify_event(attempt) == "failure" and _event_user(attempt) is not None
    }
    return len(users) >= SPRAYING_USER_THRESHOLD

# Detecta ataques a un mismo usuario desde múltiples IPs (ataque de fuerza bruta distribuido)
def detect_distributed_brute_force(events):
    by_user = {}
    for event in events:
        user = _event_user(event)
        if user is None:
            continue
        if classify_event(event) == "failure":
            by_user.setdefault(user, set()).add(event.ip_address)
    return [
        {"user": user, "ips": sorted(ip_set), "numberOfIPs": len(ip_set)}
        for user, ip_set in by_user.items()
        if len(ip_set) > 1
    ]

# Orquestador de funciones
def detect_brute_force_by_ip(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        rapid = detect_rapid_brute_force(records)
        persistent = detect_persistent_brute_force(records)
        spraying = detect_spraying_brute_force(records)

        if not (rapid or persistent or spraying):
            continue

        results.append(SimpleNamespace(
            ip_address=ip_value,
            rapid=rapid,
            persistent=persistent,
            spraying=spraying,
        ))
        
    return results

# Detecta conexiones múltiples de un mismo usuario desde diferentes IPs en una ventana de tiempo específica
def multi_connections(events, window_minutes=5):
    successful = _successful_events(events)
    by_user = {}
    # Agrupo eventos por usuario
    for event in successful:
        user = _event_user(event)
        if user is None:
            continue
        by_user.setdefault(user, []).append(event)
    # Recorro cada usuario y sus eventos, y busco ventanas de tiempo donde haya multiples IPs
    results = []
    for user, user_events in by_user.items():
        user_alerts = []
        for window in _events_in_window(user_events, window_minutes=window_minutes):
            ips_in_window = {event.ip_address for event in window}
            if len(ips_in_window) <= 1:
                continue

            start = window[0].timestamp
            end = window[-1].timestamp

            if isinstance(start, str):
                start = datetime.fromisoformat(start)
            if isinstance(end, str):
                end = datetime.fromisoformat(end)

            if user_alerts and start <= user_alerts[-1]["end"]:
                previous = user_alerts[-1]
                previous["ips"].update(ips_in_window)
                previous["end"] = max(previous["end"], end)
            else:
                user_alerts.append({
                    "user": user,
                    "ips": set(ips_in_window),
                    "start": start,
                    "end": end,
                })

        for alert in user_alerts:
            alert["ips"] = sorted(alert["ips"])
            alert["numberOfIPs"] = len(alert["ips"])
            results.append(alert)
        
    return results
    
# Detecta conexiones geograficamente distribuidas de un mismo usuario desde diferentes IPs en una ventana de tiempo específica
def geo_connections(events, window_minutes=5):
    successful = _successful_events(events)
    by_user = {}
    # Agrupo eventos por usuario
    for event in successful:
        user = _event_user(event)
        if user is None:
            continue
        by_user.setdefault(user, []).append(event)
    # Recorro cada usuario y sus eventos, y busco ventanas de tiempo donde haya multiples IPs
    results = []
    database_path = Path(__file__).with_name("ipinfo_lite.mmdb")
    with maxminddb.open_database(database_path) as reader:
        for user, user_events in by_user.items():
            user_alerts = []
            for window in _events_in_window(user_events, window_minutes=window_minutes):
                ips_in_window = {event.ip_address for event in window}
                if len(ips_in_window) <= 1:
                    continue
                # Analizo la geolocalización de las IPs para determinar si están distribuidas geográficamente
                countries = set()
                for ip in ips_in_window:
                    if _is_private_ip(ip):
                        continue
                    try:
                        response = reader.get(ip)
                        country = response.get("country_code") if response else None
                        # Aquí podrías almacenar la información de geolocalización para cada IP y luego analizar si están distribuidas geográficamente
                        if country:
                            countries.add(country)
                    except ValueError:
                        print(f"IP inválida: {ip}")
                    except KeyError:
                        print(f"IP no encontrada en la base GeoIP: {ip}")

                if len(countries) > 1:
                    start = window[0].timestamp
                    end = window[-1].timestamp

                    if isinstance(start, str):
                        start = datetime.fromisoformat(start)
                    if isinstance(end, str):
                        end = datetime.fromisoformat(end)

                    if user_alerts and start <= user_alerts[-1]["end"]:
                        previous = user_alerts[-1]
                        previous["ips"].update(ips_in_window)
                        previous["countries"].update(countries)
                        previous["end"] = max(previous["end"], end)
                    else:
                        user_alerts.append({
                            "user": user,
                            "ips": set(ips_in_window),
                            "countries": set(countries),
                            "start": start,
                            "end": end,
                        })

            for alert in user_alerts:
                alert["user"] = user
                alert["ips"] = sorted(alert["ips"])
                alert["countries"] = sorted(alert["countries"])
                alert["numberOfIPs"] = len(alert["ips"])
                alert["numberOfCountries"] = len(alert["countries"])
                alert["start"] = alert["start"].isoformat() if isinstance(alert["start"], datetime) else alert["start"]
                alert["end"] = alert["end"].isoformat() if isinstance(alert["end"], datetime) else alert["end"] 
                results.append(alert)

    return results

# Detecta conexiones fuera del horario normal de un mismo usuario desde diferentes IPs
def out_horary_connections(events):
    successful = _successful_events(events)
    by_user = {}
    # Agrupo eventos por usuario
    for event in successful:
        user = _event_user(event)
        if user is None:
            continue
        by_user.setdefault(user, []).append(event)
    
    # Recorro cada usuario, calculo el promedio de la hora inferior y superior de los intentos exitosos 
    # y busco conexiones que esten fuera del horario normal
    results = []
    for user, user_events in by_user.items():
        
        # Tomo todas las horas de los intentos y los guardo en una lista de minutos
        minutes = [
            _hour_to_minutes(event.hour)
            for event in user_events
            if getattr(event, "hour", None) is not None
        ]
        if not minutes:
            continue

        #Ordeno la lista 
        ordered = sorted(minutes)
        #Tomo un limite inf y sup porque un usuario puede iniciar sesion a la mañana y al mediodia despues de almorzar por ejemplo
        lower_minutes = ordered[:5]
        upper_minutes = ordered[-5:]

        lower_avg = sum(lower_minutes) / len(lower_minutes)
        upper_avg = sum(upper_minutes) / len(upper_minutes)

        tolerance = 60  # Una hora

        lower_bound = max(0, lower_avg - tolerance)
        upper_bound = min(24 * 60 - 1, upper_avg + tolerance)

        #Segundo recorrido para buscar conexiones que esten fuera del horario normal
        for event in user_events:
            hour_value = _to_hour_value(getattr(event, "hour", None))
            if hour_value is None:
                continue
            event_minutes = _hour_to_minutes(hour_value)
            if event_minutes < lower_bound or event_minutes > upper_bound:
                results.append({
                    "user": user,
                    "ip": event.ip_address,
                    "hour": hour_value,
                    "lower_avg_hour": lower_avg,
                    "upper_avg_hour": upper_avg,
                    "lower_bound": lower_bound,
                    "upper_bound": upper_bound,
                })
    return results

# Orquestador de funciones para detectar anomalias
def detect_anomalias(events, window_minutes=5):
    return {
        "multi_connections": multi_connections(events, window_minutes=window_minutes),
        "geo_connections": geo_connections(events, window_minutes=window_minutes),
        "out_horary_connections": out_horary_connections(events),
    }