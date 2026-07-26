from models import Event
import re 
from dataclasses import dataclass


def parse_log():

    registros = []

    patron = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<hour>\d{6})\s+'
        r'(?P<action>\w+)\s+'
        r'user=(?P<user_id>\w+)\s+'
        r'ip=(?P<ip_address>\d+\.\d+\.\d+\.\d+)'
    )

    #Lectura del log linea a linea
    with open("activity.log", "r") as archivo:
        for linea in archivo:
            m = re.search(patron, linea)
            if m:
                # Agrego un registro de tipo Evento con los datos extraídos
                registros.append(Event(m.group("timestamp"), m.group("hour"), m.group("action"), m.group("user_id"), m.group("ip_address")))
    
    
    return registros