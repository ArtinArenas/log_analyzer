from parser import parse_log
from detector import attempts_for_ip, brute_force_for_ip, failed_attempts_for_ip, public_ips, suspicious_activity_by_hour
from reports import imp_report

records = parse_log("./log_ssh.log")
#records = parse_log("./activity.log")
attempts = attempts_for_ip(records)
failed_attempts = failed_attempts_for_ip(records)
brute_force = brute_force_for_ip(records)
suspicious_activity = suspicious_activity_by_hour(records, hour_inferior="000000", hour_superior="050000")
public_ips = public_ips(records)

print("\n\nIntentos: ")
imp_report(attempts)

print("\n\nIntentos fallidos: ")
imp_report(failed_attempts)

print("\n\nFuerza bruta: ")
imp_report(brute_force)

print("\n\nActividad sospechosa: ")
imp_report(suspicious_activity)

print("\n\nIPs públicas: ")
imp_report(public_ips)