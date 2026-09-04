import os
import urllib.request
from importlib import import_module
from models import classify_event, Event, normalize_outcome, normalize_action
from ipaddress import ip_address
from types import SimpleNamespace
from datetime import datetime, timedelta
import config


try:
    import_module("dotenv").load_dotenv()
except ImportError:
    pass

# El usuario debe configurar su token gratuito de IPinfo en su entorno
#TOKEN = os.getenv("IPINFO_TOKEN")
DB_NAME = "ipinfo_lite.mmdb"

def descargar_base_datos():
    if not config.IPINFO_TOKEN:
        print("Error: Necesitas configurar la variable de entorno IPINFO_TOKEN.")
        return False
        
    # URL de descarga directa para el formato MMDB
    url = f"https://ipinfo.io/data/ipinfo_lite.mmdb?token={config.IPINFO_TOKEN}"
    
    print("\nDescargando la base de datos de IPinfo actualizada...")
    try:
        urllib.request.urlretrieve(url, DB_NAME)
        print("\nBase de datos descargada con éxito.")
        return True
    except Exception as e:
        print(f"\nError al descargar: {e}")
        return False


###############################################################################################################################
# Funciones para detectores
###############################################################################################################################
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


def public_ips(events):
    grouped = _group_by_ip(events)
    results = []
    for ip_value, records in grouped.items():
        if _is_private_ip(ip_value):
            continue
        results.extend(records)
    return results

def _successful_events(events):
    return [event for event in events if classify_event(event) == "success"]

# Agrupa eventos por ventanas de tiempo
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
###############################################################################################################################
# Funciones para la cabera de los reportes
###############################################################################################################################

# Retorna la cantidad de conexiones
def count_registros(events):
    return len(events)

# Retorna la cantidad de conexiones fallidas
def count_registros_failed(events):   
    return len([event for event in events if classify_event(event) == "failure"])

# Obtiene la fecha del primer registro
def get_first_record_date(events):
    first_record = None
    for record in events:
        if first_record is None or record.timestamp < first_record.timestamp:
            first_record = record
    return first_record.timestamp if first_record else None

# Obtiene la fecha del ultimo registro
def get_last_record_date(events):
    last_record = None
    for record in events:
        if last_record is None or record.timestamp > last_record.timestamp:
            last_record = record
    return last_record.timestamp if last_record else None