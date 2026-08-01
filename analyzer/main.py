from parser import parse_log
from detector import attempts_for_ip
from reports import imp_report

records = parse_log()
attempts = attempts_for_ip(records)

print("\n\nIntentos: ")
imp_report(attempts)