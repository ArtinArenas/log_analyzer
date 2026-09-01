from parser import parse_log
from detector import attempts_for_ip, brute_force_for_ip, failed_attempts_for_ip, public_ips, suspicious_activity_by_hour, detect_brute_force_by_ip
from reports import imp_report
import argparse # biblioteca para argumentos de línea de comandos


parser = argparse.ArgumentParser(description="Analizador de Logs \n [OPTIONS] [log file path]\n")

# Argumento opcional
parser.add_argument("--attempts", "-a", action="store_true", help="Muestra los intentos de conexión por IP")
parser.add_argument("--failed_attempts", "-f", action="store_true", help="Muestra los intentos fallidos de conexión por IP")
parser.add_argument("--brute_force", "-b", action="store_true", help="Muestra los intentos fallidos de fuerza bruta por IP")
parser.add_argument("--suspicious_activity", "-s", nargs='*', default=argparse.SUPPRESS, metavar=("hora_min", "hora_max"), help="Muestra la actividad sospechosa por hora. Se deben ingresar dos horas en formato HHMMSS. Valores dafualt: 000000 050000")
parser.add_argument("--public_ips", "-p", action="store_true", help="Muestra las IPs públicas que se conectaron al servidor")
# Argumento posicional
parser.add_argument("log_file", type=str, help="Ruta al archivo de log")

args = parser.parse_args()

records = parse_log(args.log_file)

if args.attempts:
    attempts_res = attempts_for_ip(records)
    print("\n\nIntentos: ")
    print(attempts_res)
    #imp_report(attempts_res)

if args.failed_attempts:
    failed_attempts_res = failed_attempts_for_ip(records)
    print("\n\nIntentos fallidos: ")
    print(failed_attempts_res)
    #imp_report(failed_attempts_res)

if args.brute_force:
    brute_force_res = detect_brute_force_by_ip(records)
    print("\n\nFuerza bruta: ")
    print(brute_force_res)
    #imp_report(brute_force_res)

# hasattr para evitar el AttributeError por el default de argparse.SUPPRESS
if hasattr(args, "suspicious_activity"):
    valores = args.suspicious_activity
    
    # si el usuario mando solo "-s"
    if len(valores) == 0:
        hora_min, hora_max = "000000", "050000"
        
    # si el usuario mando las dos horas
    elif len(valores) == 2:
        hora_min, hora_max = valores[0], valores[1]
        
    # cantidad incorrecta de horas
    else:
        parser.error("La opción -s requiere exactamente dos horas (HHMMSS) o ninguna para usar valores por defecto.")

    suspicious_activity_res = suspicious_activity_by_hour(
        records, 
        hour_inferior=hora_min, 
        hour_superior=hora_max
    )

    print("\n\nActividad sospechosa: ")
    imp_report(suspicious_activity_res)

if args.public_ips:
    public_ips_res = public_ips(records)
    print("\n\nIPs públicas: ")
    imp_report(public_ips_res)
