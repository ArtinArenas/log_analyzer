# log_analyzer
Python tool for detecting suspicious authentication activity in Event Logs.

###########

Objetos:
    Event: (Obsoleto) Reemplazado por Detail.
    Detail: Objeto que se completa con los datos extraidos del log.
    DetalleIntentos: Objeto retornado por la funcion attempts_for_ip.
    DetalleIntentosHora: Objeto retornado por la funcion suspicious_activity_by_hour.
    BruteForceResult: Objeto retornado por la funcion detect_brute_force_by_ip
    DetalleBruteForce: Objeto usado para crear listas para BruteForceResult.compromise, almacena todos los usuarios comprometidos por una misma ip y la cantidad de intentos fallidos que necesito para comprometer cada uno y sus intentos exitosos.
    


###########

Detectores:
    
    attempts_for_ip(events): 
        INPUT: Recibe un diccionario con una direccion IP como clave y una lista de objetos Detail con los intentos para esa IP (un hashmap con lista). 

        OUTPUT: Retorna una lista de objetos DetalleIntentos.

        FUNCION: Para cada IP recorre la lista de eventos e informa cantidad de intentos exitosos, cantidad de intentos fallidos, lista de usuarios con los que se realizo un intento exitoso, lista de usuarios con los que se realizo un intento fallido.

    suspicious_activity_by_hour(events, hour_inferior, hour_superior)
        INPUT: Recibe un diccionario con una direccion IP como clave y una lista de objetos Detail con los intentos para esa IP (un hashmap con lista). OPCIONAL: Recibe hora desde y hora hasta, valores por dafault 00:00:00 - 05:00:00.

        OUTPUT: Retorna una lista de objetos DetalleIntentosHora.

        FUNCION: Detecta intentos sospechosos en horas de poca actividad.

    detect_brute_force_by_ip(events)
        INPUT: Recibe un diccionario con una direccion IP como clave y una lista de objetos Detail con los intentos para esa IP (un hashmap con lista). 

        OUTPUT: Retorna una lista de objetos BruteForceResult.

        FUNCION: Orquestador para las funciones de deteccion de fuerza bruta (detect_rapid_brute_force, detect_persistent_brute_force, detect_possible_compromise, detect_spraying_brute_force), recorre el diccionario y le envia la lista de cada IP a las funciones para ser analizadas.

    detect_rapid_brute_force(attempts)
        INPUT: Recibe una lista de objetos Detail.
        
        OUTPUT: Retorna un boolean.

        FUNCION: Detecta la cantidad de intentos fallidos en una ventana de tiempo, si se supera el umbral se considera un ataque rapido.
    
    detect_persistent_brute_force(attempts)
        INPUT: Recibe una lista de objetos Detail.

        OUTPUT: Retorna un boolean.

        FUNCION: Detecta muchos intentos fallidos consecutivos, se considera un ataque persistente.

    detect_possible_compromise(attempts)
        INPUT: Recibe una lista de objetos Detail.

        OUTPUT: Retorna un boolean.

        FUNCION: Detecta cuando un usuario tiene muchos inicios fallidos y despues uno exitoso, el usuario puede estar comprometido

    detect_spraying_brute_force(attempts)
        INPUT: Recibe una lista de objetos Detail.

        OUTPUT: Retorna un boolean.

        FUNCION: Detecta muchos intentos de una misma ip con distintos usuarios
    