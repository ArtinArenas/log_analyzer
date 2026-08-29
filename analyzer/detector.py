
# Lógica para la detección de eventos
from datetime import datetime, time, timedelta

from models import DetalleIntentos, DetalleIntentosHora, BruteForceResult, DetalleBruteForce, classify_event
from utils import (
    _build_alert_from_record,
    event_ip,
    event_location,
    event_timestamp,
    event_user,
    flatten_events,
)

# Detecta intentos de login agrupados por IP. 
# Devuelve un lista con ip, cant de accesos/usuario fallidos y exitosos.
# Input: hashmap con ip como clave y lista de eventos como valor.
# Output: lista de objetos DetalleIntentos
def attempts_for_ip(events):
    # Errores posibles:
    # - DetalleIntentos exige cinco argumentos en su constructor, pero se instancia sin ninguno. ✔
    # - El parser entrega objetos Detail, no diccionarios; attempt["result"] provocaria TypeError. ✔
    # - Se usa value.user en vez de attempt.user, y len(value) se suma por cada evento, inflando los conteos. ✔
    # - Se comparan resultados en minuscula, aunque el parser puede conservar valores como LOGIN_FAILED. (La modificacion debe ir en el parser para que result solo pueda ser success o failed)
    # Errores adicionales posibles:
    # - DetalleIntentos no esta importado desde models.py, por lo que su uso produce NameError.
    # - El cuerpo de `for key, value in events.items()` debe estar indentado; tal como esta escrito, produce IndentationError. ✔
    # - La funcion espera un diccionario con `.items()`, pero si recibe la lista de Detail que usan algunos tests produce AttributeError.
    # - `DetalleIntentos.attempts` se calcula solo al construir el objeto; incrementar los contadores despues no actualiza ese total.
    # - Si una IP no tiene intentos fallidos ni exitosos reconocibles, se agrega igualmente un detalle vacio.
    ip = []
    
    for key, value in events.items():
        detalle = DetalleIntentos(
            ip_address=key,
            attempts_failed=0,
            failed_user_ids=[],
            attempts_success=0,
            successful_user_ids=[]
        )

        for attempt in value:
            if attempt.result == "failed":
                detalle.attempts_failed += 1
                detalle.failed_user_ids.append(attempt.user)

            elif attempt.result == "success":
                detalle.attempts_success += 1
                detalle.successful_user_ids.append(attempt.user)

        ip.append(detalle)
        
    
    return ip



# Detecta horas con una concentración sospechosa de eventos.
# Input: hashmap con ip como clave y lista de eventos como valor.
# Output: lista de objetos DetalleIntentosHora 
def suspicious_activity_by_hour(events, hour_inferior, hour_superior):
    # Errores posibles:
    # - El bloque if contiene una sintaxis invalida y el modulo no puede importarse. ✔
    # - DetalleIntentosHora se referencia como clase y no se instancia con sus argumentos obligatorios. ✔
    # - Detail.timestamp se crea como texto en el parser, por lo que no necesariamente dispone de .time(). (modificar en parse)
    # - Los limites pueden llegar como cadenas HHMMSS desde main.py y no se pueden comparar con datetime.time. ✔
    # - Se reutiliza un unico detalle para todas las IP y se consultan atributos que no fueron inicializados. ✔
    suspicious_activity = []
    
    if hour_inferior is None:
        hour_inferior = time(0,0,0) # Hora default
    else:
        hour_inferior = datetime.strptime(hour_inferior, "%H%M%S").time() # Transformo el string en un objeto time
    if hour_superior is None:
        hour_superior = time(5,0,0) # Hora default
    else:
        hour_superior = datetime.strptime(hour_superior, "%H%M%S").time() # Transformo el string en un objeto time


    for key, value in events.items():
        detalle = DetalleIntentosHora(
            ip_address = key,
            attempts_failed=0,
            failed_user_ids=[],
            attempts_success=0,
            successful_user_ids=[],
            hour_inferior = hour_inferior,
            hour_superior = hour_superior
        )

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
    # Errores posibles:
    # - BruteForceResult define _init_ en vez de __init__ y se instancia sin argumentos; ambas cosas impiden crear el resultado esperado. ✔
    # - El modelo documenta compromise como lista de DetalleBruteForce, pero aqui se asigna directamente el retorno del detector. ✔
    # - El contrato del README habla de una lista de BruteForceResult, mientras que los detectores internos no comparten un tipo de retorno. ✔
    # - Si attempts contiene Detail, los detectores deben usar una representacion consistente de result y timestamp. (se cambia en el parse)
    
    brute_force_results = []

    for key, value in events.items():

        brute_force = BruteForceResult(
            ip_address = key,
            rapid = False,
            persistent = False,
            compromise = [], #Lista DetalleBruteForce
            spraying = False
        )

        brute_force.rapid= detect_rapid_brute_force(value)
        brute_force.persistent = detect_persistent_brute_force(value)
        brute_force.compromise = detect_possible_compromise(value)
        brute_force.spraying = detect_spraying_brute_force(value)

        brute_force_results.append(brute_force)

    return brute_force_results


# Analiza la cantidad de intentos fallidos en una ventana de tiempo para detectar un ataque rapido
def detect_rapid_brute_force(attempts):
    # Errores posibles:
    # - Se accede a attempt.result directamente y se compara con "failed", aunque classify_event ya existe para normalizar resultados.
    # - timestamp puede ser una cadena producida por el parser; restarla de otra cadena provoca TypeError.
    # - La ventana supone que attempts esta ordenado cronologicamente y no valida ese supuesto.
    # - El umbral esta fijo en diez y no forma parte de la configuracion documentada del detector.

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
    # Errores posibles:
    # - La comparacion con "failed" y "success" puede fallar con los valores LOGIN_FAILED y LOGIN_SUCCESS del modelo/parser.
    # - Solo un exito reinicia la secuencia; eventos desconocidos quedan incluidos implicitamente en la misma racha.
    # - El resultado depende del orden de la lista y no comprueba que los intentos sean consecutivos en el tiempo.
    # - El umbral fijo de treinta no esta expuesto ni justificado en el contrato del README.
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
    # Errores posibles:
    # - DetalleBruteForce requiere user, failedAttempts y compromise, pero se instancia sin argumentos.
    # - Se compara attempt.result sin normalizacion, por lo que los resultados del parser pueden no activar la logica.
    # - Tras un exito comprometedor se conserva failedAttempts y el filtro final puede devolver usuarios aunque el estado no se consulte.
    # - El retorno es un diccionario, aunque BruteForceResult.compromise se documenta como una lista de DetalleBruteForce.
    # - La deteccion depende del orden de attempts y no reinicia el contador al cambiar de ventana temporal.
    # Si supera la cantidad de threadhold y despues hay un exitoso, posible ataque exitoso
    threshold = 10

    usersDict = {}

    for attempt in attempts:
        #Obtengo el usuario o seteo valores dafaults
        user = usersDict.get(attempt.user)
        if user is None:
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
        
    
    #Retorno una lista de tipo DetalleBruteForce con los usuarios comprometidos
    return [user for user in usersDict.values() if user.compromise == 1]


# Muchos intentos de una misma ip con distintos usuarios. (PASSWORD SPRAYING)
def detect_spraying_brute_force(attempts):
    # Errores posibles:
    # - El umbral fijo de tres usuarios no esta definido en README ni recibe configuracion.
    # - Solo cuenta usuarios con fallos; intentos exitosos o usuarios ausentes quedan fuera aunque pueden ser relevantes para el analisis.
    # - event_user depende de una forma concreta del objeto y puede producir resultados inconsistentes con Detail.user.
    # - La funcion solo es correcta cuando attempts ya corresponde a una unica IP, condicion que el llamador debe garantizar.
    # Esta funcion creo que puede ser evitable, si en las funciones anteriores almaceno la cantidad de usuarios que 
    # levanto desde attempt.user_id y tengo mas de 3 ip (por evitar falsos positivos por un user mal tipeado o un admin que usa su cuenta y la de root, etc) 
    # -> posible spraying

    #Por ahora cuento la cantidad de usuarios aca para no ensuciar otras funciones
    failed_users = {
        event_user(attempt)
        for attempt in attempts
        if classify_event(attempt) == "failure" and event_user(attempt) is not None
    }
    return len(failed_users) >= 3

# Muchos intentos fallidos contra un mismo usuario desde distintas IPs. (Ataque distribuido)
'''def detect_distributed_brute_force(): ''' #Pensar como implementar
    # Este caso es distinto, no me sirve pasarle attempts, deberia pasarle un diccionario por usuario que tenga las 
    # IP desde las que intentaron conectarse (o crear el diccionario aca en base al otro).
    # Las direcciones IP tanto publicas como privadas cambian casi todos los dias. Si analizo un log de un año me va a dar
    # falsos positivos.














##############################################################################################################################
#                                           Funciones para deteccion de anomalias
##############################################################################################################################
'''
# Orquestador de anomalias.
def detect_anomalias(events, window_minutes=5, work_start=8, work_end=18):
    return {
        "multi_connections": multi_connections(events, window_minutes),
        "geo_connections": geo_connections(events, window_minutes),
        "out_horary_connections": out_horary_connections(events, work_start, work_end),
    }


def _successful_events(events):
    return [event for event in flatten_events(events) if classify_event(event) == "success"]


def _events_in_window(events, window_minutes):
    ordered = sorted(
        (event for event in events if event_timestamp(event) is not None),
        key=event_timestamp,
    )
    for index, event in enumerate(ordered):
        nearby = [event]
        for other in ordered[index + 1 :]:
            if other.timestamp - event.timestamp > timedelta(minutes=window_minutes):
                break
            nearby.append(other)
        yield nearby


# Anomalias en conexiones exitosas de un mismo usuario desde distintas IPs en poco tiempo.
def multi_connections(events, window_minutes=5):
    alerts = []
    successful = _successful_events(events)
    users = sorted({event_user(event) for event in successful if event_user(event) is not None})

    for user in users:
        user_events = [event for event in successful if event_user(event) == user]
        for window in _events_in_window(user_events, window_minutes):
            ips = sorted({event_ip(event) for event in window if event_ip(event) is not None})
            if len(ips) > 1:
                alerts.append(_build_alert_from_record(
                    window[-1], "multi_connections",
                    f"El usuario {user} inicio sesion desde {len(ips)} IPs en {window_minutes} minutos",
                    "high", len(window), user_id=[user], ip_address=ips[-1],
                    ips=ips,
                ))
                break
    return alerts


# Anomalias en conexiones exitosas de un mismo usuario desde distintas ubicaciones en poco tiempo.
def geo_connections(events, window_minutes=5):
    alerts = []
    successful = _successful_events(events)
    users = sorted({event_user(event) for event in successful if event_user(event) is not None})

    for user in users:
        user_events = [event for event in successful if event_user(event) == user]
        for window in _events_in_window(user_events, window_minutes):
            locations = sorted({event_location(event) for event in window if event_location(event) is not None})
            if len(locations) > 1:
                alerts.append(_build_alert_from_record(
                    window[-1], "geo_connections",
                    f"El usuario {user} inicio sesion desde {len(locations)} ubicaciones en {window_minutes} minutos",
                    "high", len(window), user_id=[user], ip_address=event_ip(window[-1]),
                    locations=locations,
                ))
                break
    return alerts


# Conexiones exitosas fuera del horario habitual indicado.
def out_horary_connections(events, work_start=8, work_end=18):
    alerts = []
    for event in _successful_events(events):
        timestamp = event_timestamp(event)
        if timestamp is None:
            continue
        if not work_start <= timestamp.hour < work_end:
            alerts.append(_build_alert_from_record(
                event, "out_horary_connections",
                f"Conexion exitosa fuera del horario habitual ({work_start:02d}:00-{work_end:02d}:00)",
                "medium", 1, user_id=[event_user(event)] if event_user(event) else [],
                ip_address=event_ip(event),
            ))
    return alerts

'''