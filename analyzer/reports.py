def imp_report(alerts):
    for alert in alerts:
        print(
            f"[{alert.detector}] severity={alert.severity} attempts={getattr(alert, 'attempts', 0)} "
            f"users={alert.user_id} ip={alert.ip_address}"
        )
        if alert.message:
            print(alert.message)


impReport = imp_report