def imp_report(alerts):
    for alert in alerts:
        print(
            f"\n[{alert.detector}] severity={alert.severity} attempts={getattr(alert, 'attempts', 0)} "
            f"users={alert.user_id} ip={alert.ip_address}"
        )
        if alert.message:
            print(alert.message)

        extra_fields = {
            key: value
            for key, value in vars(alert).items()
            if key not in {"timestamp", "hour", "severity", "detector", "message", "user_id", "ip_address", "attempts"}
        }
        for key, value in sorted(extra_fields.items()):
            if value is not None:
                print(f"  {key}={value}")


impReport = imp_report