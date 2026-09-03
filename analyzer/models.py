# Objeto principal que representa un evento de autenticación.
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


def normalize_action(action=None, result=None, method=None):
    action_text = str(action or "").strip().upper()
    result_text = str(result or "").strip().lower()
    method_text = str(method or "").strip().lower()

    if "FAILED" in action_text or "FAILURE" in action_text or "DENIED" in action_text:
        return "LOGIN_FAILED"
    if "SUCCESS" in action_text or "ACCEPTED" in action_text:
        return "LOGIN_SUCCESS"
    if result_text in {"failed", "failure", "denied"}:
        return "LOGIN_FAILED"
    if result_text in {"accepted", "success", "successfully"}:
        return "LOGIN_SUCCESS"
    if method_text in {"password", "publickey"}:
        if result_text in {"accepted", "success", "successfully"}:
            return "LOGIN_SUCCESS"
        return "LOGIN_FAILED"
    if action_text in {"LOGIN", "PASSWORD", "PUBLICKEY", "AUTH", "AUTHENTICATION"}:
        if result_text in {"accepted", "success", "successfully"}:
            return "LOGIN_SUCCESS"
        return "LOGIN_FAILED"
    return "LOGIN"


def normalize_outcome(result=None, action=None):
    action_text = str(action or "").strip().lower()
    result_text = str(result or "").strip().lower()

    if "failed" in action_text or "failure" in action_text or "denied" in action_text:
        return "failure"
    if "success" in action_text or "accepted" in action_text:
        return "success"
    if result_text in {"failed", "failure", "denied"}:
        return "failure"
    if result_text in {"accepted", "success", "successfully"}:
        return "success"
    return "unknown"


def classify_event(event):
    outcome = getattr(event, "outcome", None)
    if outcome:
        return outcome

    action = getattr(event, "action", None)
    result = getattr(event, "result", None)
    return normalize_outcome(result=result, action=action)