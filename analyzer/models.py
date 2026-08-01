# Objeto donde se almacenan los registros obtenidos de los logs
class Event:
    def __init__(self, timestamp, hour, action, user_id, ip_address, attempts):
        self.timestamp = timestamp
        self.hour = hour
        self.action = action
        self.user_id = [user_id] if not isinstance(user_id, list) else user_id
        self.ip_address = ip_address
        self.attempts = attempts


# Objeto que retornan los detectores
class Alert:
    def __init__(self, timestamp, hour, severity, detector, message, user_id, ip_address, attempts=0):
        self.timestamp = timestamp
        self.hour = hour
        self.severity = severity
        self.detector = detector
        self.message = message
        self.user_id = user_id
        self.ip_address = ip_address
        self.attempts = attempts