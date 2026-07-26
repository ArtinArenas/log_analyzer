
# Objeto donde se almacenan los registros obtenidos de los logs
class Event:
    def __init__(self, timestamp, hour, action, user_id, ip_address):
        self.timestamp = timestamp      # Atributo de instancia
        self.hour = hour                # Atributo de instancia
        self.action = action            # Atributo de instancia
        self.user_id = user_id          # Atributo de instancia
        self.ip_address = ip_address    # Atributo de instancia
        

# Objeto que retornan los detectores
class Alert:
    def __init__(self, timestamp, hour, severity, detector, messaje, user_id, ip_address):
        self.timestamp = timestamp      # Atributo de instancia
        self.hour = hour                # Atributo de instancia
        self.severity = severity        # Atributo de instancia
        self.detector = detector        # Atributo de instancia
        self.messaje = messaje          # Atributo de instancia
        self.user_id = user_id          # Atributo de instancia
        self.ip_address = ip_address    # Atributo de instancia