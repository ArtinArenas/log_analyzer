# Objeto donde se almacenan los registros obtenidos de los logs
class Event:
    def __init__(
        self,
        timestamp,
        hour,
        action,
        user_id,
        ip_address,
        attempts,
        source=None,
        result=None,
        method=None,
        port=None,
        raw=None,
        outcome=None,
        **extra_fields,
    ):
        self.timestamp = timestamp
        self.hour = hour
        self.action = action
        self.user_id = [user_id] if not isinstance(user_id, list) else user_id
        self.ip_address = ip_address
        self.attempts = attempts
        self.source = source
        self.result = result
        self.method = method
        self.port = port
        self.raw = raw
        self.outcome = outcome

        for field_name, value in extra_fields.items():
            setattr(self, field_name, value)


class Detail:
    def __init__(self, timestamp, user, action, result):
        self.timestamp = timestamp
        self.user = user
        self.action = action
        self.result = result

class DetalleIntentos:
    def __init__(self, ip_address, attempts_failed, failed_user_ids, attempts_success, successful_user_ids):
        self.ip_address = ip_address
        self.attempts = attempts_failed + attempts_success
        self.attempts_failed = attempts_failed
        self.failed_user_ids = [failed_user_ids] if not isinstance(failed_user_ids, list) else failed_user_ids
        self.attempts_success = attempts_success
        self.successful_user_ids = [successful_user_ids] if not isinstance(successful_user_ids, list) else successful_user_ids

class DetalleIntentosHora(DetalleIntentos):
    def __init__(self, ip_address, attempts_failed, failed_user_ids, attempts_success, successful_user_ids, hour_inferior, hour_superior):
        super().__init__(ip_address, attempts_failed, failed_user_ids, attempts_success, successful_user_ids)
        self.hour_inferior = hour_inferior
        self.hour_superior = hour_superior

class DetalleBruteForce:
    def __init__(self, user, failedAttempts, compromise):
        self.user = user
        self.failedAttempts = failedAttempts
        self.compromise = compromise

class BruteForceResult:
    def _init_(self, ip_address, rapid, persistent, compromise, spraying):
        self.ip_address = ip_address
        self.rapid = rapid
        self.persistent = persistent
        self.compromise = [compromise] #Lista DetalleBruteForce
        self.spraying = spraying


































# Objeto que retornan los detectores
class Alert:
    def __init__(
        self,
        timestamp,
        hour,
        severity,
        detector,
        message,
        user_id,
        ip_address,
        attempts=0,
        **extra_fields,
    ):
        self.timestamp = timestamp
        self.hour = hour
        self.severity = severity
        self.detector = detector
        self.message = message
        self.user_id = user_id
        self.ip_address = ip_address
        self.attempts = attempts

        for field_name, value in extra_fields.items():
            setattr(self, field_name, value)


def build_event(**kwargs):
    return Event(**kwargs)


def build_alert(**kwargs):
    return Alert(**kwargs)


def normalize_action(action, result=None, method=None):
    if action:
        return action

    normalized_result = (result or "").strip().lower()
    if normalized_result in {"accepted", "success", "successfully"}:
        return "LOGIN_SUCCESS"
    if normalized_result in {"failed", "failure", "denied"}:
        return "LOGIN_FAILED"

    if method:
        normalized_method = method.strip().lower()
        if normalized_method in {"password", "publickey"}:
            return "LOGIN_SUCCESS" if normalized_result != "failed" else "LOGIN_FAILED"

    return "UNKNOWN"


def normalize_outcome(result=None, action=None):
    if action:
        normalized_action = action.strip().lower()
        if "failed" in normalized_action or "failure" in normalized_action or "denied" in normalized_action:
            return "failure"
        if "success" in normalized_action or "accepted" in normalized_action:
            return "success"

    normalized_result = (result or "").strip().lower()
    if normalized_result in {"accepted", "success", "successfully"}:
        return "success"
    if normalized_result in {"failed", "failure", "denied"}:
        return "failure"

    return "unknown"


def classify_event(event):
    outcome = getattr(event, "outcome", None)
    if outcome:
        return outcome

    action = getattr(event, "action", None)
    result = getattr(event, "result", None)
    return normalize_outcome(result=result, action=action)