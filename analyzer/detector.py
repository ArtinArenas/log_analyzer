from datetime import datetime, timedelta
from ipaddress import ip_address
from types import SimpleNamespace
import geoip2.database #pip install geoip2
from geoip2.errors import AddressNotFoundError

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

def _hour_to_minutes(hour_value):
    hour_value = str(hour_value).replace(":", "")

    hours = int(hour_value[:2])
    minutes = int(hour_value[2:4])

    return hours * 60 + minutes


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
            distributed=detect_distributed_brute_force(records),
        ))
    return results


def _successful_events(events):
    return [event for event in events if classify_event(event) == "success"]


# Agrupa eventos que ocurren dentro de una ventana de tiempo.
'''
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
'''
# Misma funcion que la de arriba pero usando punteros (mas eficiente).
def _events_in_window(events, window_minutes=5):
    ordered = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event.timestamp)
        if isinstance(event.timestamp, str)
        else event.timestamp,
    )

    right = 0

    for left, event in enumerate(ordered):
        if right < left:
            right = left

        start_time = event.timestamp
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)

        while right + 1 < len(ordered):
            next_time = ordered[right + 1].timestamp
            if isinstance(next_time, str):
                next_time = datetime.fromisoformat(next_time)

            if next_time - start_time > timedelta(minutes=window_minutes):
                break

            right += 1

        yield ordered[left:right + 1]

# ERROR: debe detectar multiples conexiones para un mismo usuario desde diferentes IPs en una ventana corta de tiempo, pero por ahora solo detecta multiples conexiones sin importar la ventana de tiempo. 
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
    
    
    
    
# ERROR: debe detectar conexiones geograficamente distribuidas para un mismo usuario en una ventana imposible de tiempo, pero por ahora solo devuelve el mismo resultado que multi_connections.
# Investigar como descargar .mmdb de IPinfo con el plan gratis para poder determinar la geolocalizacion
# Sin depender del limite de consultas de una API o conexiones externas (salvo por la descarga del .mmdb)
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
    with geoip2.database.Reader('ipinfo_lite.mmdb') as reader:
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
                        response = reader.country(ip)
                        country = response.country.iso_code
                        # Aquí podrías almacenar la información de geolocalización para cada IP y luego analizar si están distribuidas geográficamente
                        countries.add(country)
                    except ValueError:
                        print(f"IP inválida: {ip}")
                    except AddressNotFoundError:
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


# Error: debe, por usuario, tomar un promedio de la hora inferior y superior de los intentos exitosos y determinar si el intento de conexion está fuera del horario normal, pero por ahora solo devuelve los intentos exitosos fuera del horario laboral.
# para este punto no alcanza con promedio, debe ser promedio +- un margen de tolerancia, por ejemplo 1 hora, para determinar si está fuera del horario normal.
# para el promedio puedo tomar las 3 o 5 horas inferiores y superiores de los intentos exitosos.
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



def detect_anomalias(events, window_minutes=5):
    return {
        "multi_connections": multi_connections(events, window_minutes=window_minutes),
        "geo_connections": geo_connections(events, window_minutes=window_minutes),
        "out_horary_connections": out_horary_connections(events),
    }
