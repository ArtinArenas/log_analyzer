
# Lógica para la detección de eventos
from collections import defaultdict
from models import build_alert, classify_event
from datetime import datetime

# Detecta intentos de login agrupados por IP. 
# Devuelve un lista con ip, cant de accesos/usuario fallidos y exitosos.
# Input: hashmap con ip como clave y lista de eventos como valor.
# Output: lista de objetos DetalleIntentos
def attempts_for_ip(events):
    ip = []
    detalle = DetalleIntentos()
    
    for key, value in events.items():
        detalle.ip_address = key  
        # Agrega la IP a la lista de intentos
        if value["result"] == "failed":
            detalle.attempts_failed += len(value)
            detalle.failed_user_ids.append(value.user)

        if value["result"] == "success":
            detalle.attempts_success += len(value)
            detalle.successful_user_ids.append(value.user)
    
    return ip

# Detecta horas con una concentración sospechosa de eventos.
# Input: hashmap con ip como clave y lista de eventos como valor.
# Output: lista de objetos DetalleIntentosHora 
def suspicious_activity_by_hour(events, hour_inferior, hour_superior):
    suspicious_activity = []
    
    if(
        if hour_inferior is None:
            hour_inferior = time(0,0,0)
        if hour_superior is None:
            hour_superior = time(5,0,0)
    )

    detalle = DetalleIntentosHora

    for key, value in events.items():
        detalle.ip_address = key

        for event in value:
            #Paso la fecha a hora para hacer las comparaciones
            horaRegistro = event.timestamp.time()

            if (hour_inferior <= horaRegistro <= hour_superior):
                if event.result == "failed":
                    detalle.attempts_failed += 1
                    detalle.failed_user_ids.append(event.user)
                elif event.result == "success":
                    detalle.attempts_success += 1
                    detalle.successful_user_ids.append(event.user)
            
            #Guardo la hora inferior y superior de los registros para cada ip
            if(detalle.hour_inferior is None or horaRegistro < detalle.hour_inferior):
                detalle.hour_inferior = horaRegistro
            if(detalle.hour_superior is None or horaRegistro > detalle.hour_superior):
                detalle.hour_superior = horaRegistro
        
        suspicious_activity.append(detalle)
    
    return suspicious_activity







##############################################################################################################################
#                                           Funciones para deteccion de fuerza bruta
##############################################################################################################################

# Detecta intentos de fuerza bruta.
# Input: hashmap con ip como clave y lista de eventos como valor.
# Output: lista de objetos ...


# Orquestador de detectores de fuerza bruta
def detect_brute_force_by_ip(events):
    
    brute_force_results = []

    for ip, attempts in events.items():

        brute_force = BruteForceResult()
        brute_force.ip_address = ip

        brute_force.rapid= detect_rapid_brute_force(attempts)
        brute_force.persistent = detect_persistent_brute_force(attempts)
        brute_force.compromise = detect_possible_compromise(attempts)
        brute_force.spraying = detect_spraying_brute_force(attempts)


        brute_force_results.append(brute_force)

    return brute_force_results


# Analiza la cantidad de intentos fallidos en una ventana de tiempo para detectar un ataque rapido
def detect_rapid_brute_force(attempts):

    threshold = 10  # Umbral de intentos fallidos para considerar fuerza bruta
    minute_window = 1  # Ventana de tiempo en minutos para considerar los intentos fallidos

    #Me armo una lista de intentos fallidos
    failed_attempts = [
        attempt
        for attempt in attempts
        if attempt.result == "failed"
    ]

    for i in range(len(failed_attempts) - threshold + 1): # resto para evitar index error

        # Si la diferencia entre el registro que estoy viendo y el registro que esta a threshold posiciones 
        # adelante es menor a minute_window -> posible brute force
        if failed_attempts[i + threshold - 1].timestamp - failed_attempts[i].timestamp <= timedelta(minutes=minute_window): 
            return True
    
    return False

# Analiza muchos intentos fallidos consecutivos, detecta ataques persistentes donde se intenta una contraseña cada pocos segundos
def detect_persistent_brute_force(attempts):
    threshold = 30
    fallidos_consecutivos = 0

    for attempt in attempts:
        if attempt.result == "failed":
            fallidos_consecutivos += 1
        elif attempt.result == "success":
            fallidos_consecutivos = 0
        
        if(fallidos_consecutivos >= threshold): #Intento detectado
            return True
    
    return False

# Analiza cuando un usuario puede estar posiblemente comprometido
def detect_possible_compromise(attempts):
    # Si supera la cantidad de threadhold y despues hay un exitoso, posible ataque exitoso
    threshold = 10

    usersDict = {}

    for attempt in attempts:
        #Obtengo el usuario o seteo valores dafaults
        user = usersDict.get(attempt.user)
        if(user is None):
            user = DetalleBruteForce() # Instancio el objeto
            user.user = attempt.user
            user.failedAttempts = 0
            user.compromise = 0

        if(user.compromise == 0): #Si ya se que esta comprometido no lo sigo analizando
            if attempt.result == "failed":
                #inserto o actualizo el contador del usuario
                user.failedAttempts += 1

            elif attempt.result == "success":
                if user.failedAttempts < threshold:
                    user.failedAttempts = 0 #Si no supero el thredhold reinicio el contador
                else:
                    user.compromise = 1 #Usuario comprometido
            
            #Actualizo/agrego el objeto al dic
        
        usersDict[attempt.user] = user
        
    
    #Retorno el diccionario Usuario:CantidadDeIntentos cuando la cantidadIntentos es mayor a threshold -> retorna usuarios comprometidos y sin comprometer
    return {k: v for k, v in usersDict.items() if v.failedAttempts >= threshold}


# Muchos intentos de una misma ip con distintos usuarios. (PASSWORD SPRAYING)
def detect_spraying_brute_force(attempts):
    # Esta funcion creo que puede ser evitable, si en las funciones anteriores almaceno la cantidad de usuarios que 
    # levanto desde attempt.user_id y tengo mas de 3 ip (por evitar falsos positivos por un user mal tipeado o un admin que usa su cuenta y la de root, etc) 
    # -> posible spraying

    #Por ahora cuento la cantidad de usuarios aca para no ensuciar otras funciones
    if len(set(attempts.user)) >= 3 # Deberian solo intentos fallidos? 
        return True 
    return False

# Muchos intentos fallidos contra un mismo usuario desde distintas IPs. (Ataque distribuido)
'''def detect_distributed_brute_force(): ''' #Pensar como implementar
    # Este caso es distinto, no me sirve pasarle attempts, deberia pasarle un diccionario por usuario que tenga las 
    # IP desde las que intentaron conectarse (o crear el diccionario aca en base al otro).
    # Las direcciones IP tanto publicas como privadas cambian casi todos los dias. Si analizo un log de un año me va a dar
    # falsos positivos.














##############################################################################################################################
#                                           Funciones para deteccion de anomalias
##############################################################################################################################

#Orquestador de anomalias
def detect_anamalias():

# Anomalias en conexiones exitosas de un mismo usuario desde distintas ip's en poco tiempo.
def multi_connections():

# Anomalias en conexiones exitosas de un mismo usuario desde distintas ubicaciones geográficas en un periodo de tiempo muy corto.
def geo_connections():

# conexiones fuera de horario (login 3am cuando normalmente ese usuario trabaja de: 08:00 - 18:00) ## No me parece muy grave -> Para desarrollar en un futuro
def out_horary_connections():

