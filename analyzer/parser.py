import re
from datetime import datetime

from models import Event, Detail, build_event, normalize_action, normalize_outcome

# Funciones para parsear los logs
# Inpput: path al archivo de log
# Output: hasmap donde la clave es la ip y el valor es una lista de objetos tipo Detail

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


# Funcion para leer la primera linea del archivo de log (para determinar que parser usar)
def _read_log_content(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return ""

# Funcion que contiene logica para decidir a que parser enviar el archivo de log
def parse_log(path="log_ssh.log"):
    content = _read_log_content(path)

    if "sshd[" in content or "Accepted" in content or "Failed" in content:
        return openSsh_parser(path)

    return example_parser(path)


#2026-07-20 081532 LOGIN_SUCCESS user=juan ip=192.168.1.15
#2026-07-20 081535 LOGIN_FAILED user=admin ip=192.168.1.15
def example_parser(path="activity.log"):
    
    hashmap = {} 
    pattern = re.compile(
        r"(?P<year>\d{4})-"
        r"(?P<month>\d{2})-"
        r"(?P<day>\d{2})\s+"
        r"(?P<hour>\d{2})"
        r"(?P<minute>\d{2})"
        r"(?P<second>\d{2})\s+"
        r"(?P<action>\w+)_\s+"
        r"(?P<result>\w+)\s+"
        r"user=(?P<user_id>\w+)\s+"
        r"ip=(?P<ip_address>\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    
                    #Formateo de la fecha y hora
                    date_objet = datetime(
                        year=int(match.group('year')),
                        month=int(match.group('month')),
                        day=int(match.group('day')),
                        hour=int(match.group('hour')),
                        minute=int(match.group('minute')),
                        second=int(match.group('second'))
                    )
                    date_format = date_objet.isoformat()

                    #Guardo los resultados en un objeto tipo Detail
                    detail = Detail(
                        date_format,            # Fecha y hora
                        match.group("user_id"), # Usuario
                        match.group("action"),  # Accion
                        match.group("result")   # Resultado de la accion
                    )

                    #Inserto los datos en el hashmap, donde la clave es la ip y el valor es una lista de objetos tipo Detail
                    hashmap.setdefault(match.group("ip_address"), []).append(detail)
                
    except FileNotFoundError:
        return []

    return hashmap


#dic 10 22:17:27 debian sshd[16518]: Accepted password for paco from 192.168.1.47 port 49746 ssh2
#ago 01 14:16:02 debian sshd[2893]: Failed password for invalid user root from 192.168.1.37 port 40340 ssh2
#ago 01 14:18:27 debian sshd[2915]: Accepted publickey for juan from 192.168.1.37 port 38816 ssh2: ED25519 SHA256:w0z/sKhv9BpomD9XjxOL0kSokngs+qpAhpjYHpaX+KA

def openSsh_parser(path="log_ssh.log"):
    hashmap = {}

    pattern = re.compile(
        r"(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<hour>\d{2}):+"
        r"(?P<minute>\d{2}):+"
        r"(?P<second>\d{2})\s+"
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
                if match:
                
                #Formateo de la fecha y hora
                date_objet = datetime(
                    #Mas adelante ver de leer el archivo alreves soponiendo que el ultimo registro es del año actual y 
                    #calcular otros años cuando pasa de enero 1 a diciembre 31
                    year= datetime.now().year,  #Por ahora le hardcodeo el año actual
                    month= MONTHS.get(match.group('month')),
                    day=int(match.group('day')),
                    hour=int(match.group('hour')),
                    minute=int(match.group('minute')),
                    second=int(match.group('second'))
                )
                date_format = date_objet.isoformat()

                #Guardo los resultados en un objeto tipo Detail
                detail = Detail(
                    date_format,            # Fecha y hora
                    match.group("user_id"), # Usuario
                    match.group("action"),  # Accion
                    match.group("result")   # Resultado de la accion
                )

                #Inserto los datos en el hashmap, donde la clave es la ip y el valor es una lista de objetos tipo Detail
                hashmap.setdefault(match.group("ip_address"), []).append(detail)
    
    except FileNotFoundError:
        return []

    return hashmap

