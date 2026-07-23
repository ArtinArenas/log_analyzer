
# Logica para la deteccion de eventos

import models

# Detectar intentos de login por ip
def attemptsForIp(eventos):
    # Diccionario que almacena la cantidad de intentos por ip
    attempts = {}
    for evento in eventos:
        # Si existe sumo un intento, sino lo agrego al diccionario
        attempts.update({evento.ip_address: attempts.get(evento.ip_address, 0) + 1})
    
    return attempts

# Detectar intentos fallidos por ip
def failedAttemptsForIp(eventos):
    # Diccionario que almacena la cantidad de intentos fallidos por ip
    failed = {}
    for evento in eventos:
        if evento.action == "LOGIN_FAILED":
            failed.update({evento.ip_address: failed.get(evento.ip_address, 0) + 1})
    
    return failed

# Detectar fuerza bruta por ip
def bruteForceForIp(eventos, threshold=5):
    # Diccionario que almacena la cantidad de intentos fallidos por ip
    failed = {}
    for evento in eventos:
        if evento.action == "LOGIN_FAILED":
            failed.update({evento.ip_address: failed.get(evento.ip_address, 0) + 1})
    
    # Filtrar las ip que superan el umbral
    brute_force = {ip: count for ip, count in failed.items() if count >= threshold}
    
    return brute_force

# Detectar horarios de actividad sospechosa
def suspiciousActivityByHour(eventos, hourInferior, hourSuperior):
    # Diccionario que almacena la cantidad de intentos fallidos por hora
    failed = {}
    for evento in eventos:
        failed.update({evento.hour: failed.get(evento.hour, 0) + 1})
    
    # Filtrar las horas que esten en el umbral
    suspicious_hours = {hour: count for hour, count in failed.items() if hour >= hourInferior and hour <= hourSuperior}
    
    return suspicious_hours

# Detectar ips publicas
'''
def publicIps(eventos):
    # Diccionario que almacena la cantidad de intentos fallidos por ip
    failed = {}
    for evento in eventos:
        if evento.action == "LOGIN_FAILED":
            failed.update({evento.ip_address: failed.get(evento.ip_address, 0) + 1})
    
    # Filtrar las ip que sean publicas
    #public_ips = {ip: count for ip, count in failed.items() if not isPrivateIp(ip)}
    public_ips = {ip: count for ip, count in failed.items() if not is_Private(ip)}
    
    return public_ips
'''