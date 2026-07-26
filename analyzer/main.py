from parser import parse_log
import models
from detector import * #attemptsForIp, failedAttemptsForIp

registros = parse_log()
for registro in registros:
    print(f"Timestamp: {registro.timestamp}, Hour: {registro.hour}, Action: {registro.action}, User ID: {registro.user_id}, IP Address: {registro.ip_address}")

attempts = attemptsForIp(registros)
failed = failedAttemptsForIp(registros)
#brute_force = bruteForceForIp(registros)
brute_force = bruteForceForIp(registros, 3)
#suspicious_hours = suspiciousActivityByHour(registros, "002200", "060000")
suspicious_hours = suspiciousActivityByHour(registros, "000000", "050000")
#public_ips = publicIps(registros)

print(attempts)

print("\n\nIntentos fallidos por IP:")
print(failed)

print("\n\nFuerza bruta por IP:")
print(brute_force)

print("\n\nActividad sospechosa por hora:")
print(suspicious_hours)