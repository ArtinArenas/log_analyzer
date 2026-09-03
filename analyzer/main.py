from parser import parse_log
from reports import imp_report
import argparse


parser = argparse.ArgumentParser(description="Analizador de Logs \n [OPTIONS] [log file path]\n")

# Argumento opcional
parser.add_argument("--attempts", "-a", action="store_true", help="Muestra los intentos de conexión por IP")
parser.add_argument("--failed_attempts", "-f", action="store_true", help="Muestra los intentos fallidos de conexión por IP")
parser.add_argument("--brute_force", "-b", action="store_true", help="Muestra los intentos fallidos de fuerza bruta por IP")
parser.add_argument("--compromise", "-c", action="store_true", help="Muestra posibles usuarios comprometidos")
parser.add_argument("--distributed", "-d", action="store_true", help="Muestra fuerza bruta distribuida")
parser.add_argument("--multi_connections", "-m", action="store_true", help="Muestra conexiones múltiples del mismo usuario")
parser.add_argument("--geo_connections", "-g", action="store_true", help="Muestra conexiones del mismo usuario desde distintos países")
parser.add_argument("--out_horary_connections", "-o", action="store_true", help="Muestra conexiones fuera del horario habitual")
parser.add_argument("--suspicious_activity", "-s", nargs='*', default=argparse.SUPPRESS, metavar=("hora_min", "hora_max"), help="Muestra la actividad sospechosa por hora. Se deben ingresar dos horas en formato HHMMSS. Valores dafualt: 000000 050000")
parser.add_argument("--public_ips", "-p", action="store_true", help="Muestra las IPs públicas que se conectaron al servidor")
# Argumento posicional
parser.add_argument("log_file", type=str, help="Ruta al archivo de log")

args = parser.parse_args()

records = parse_log(args.log_file)

hora_min = None
hora_max = None
if hasattr(args, "suspicious_activity"):
    valores = args.suspicious_activity
    if len(valores) == 2:
        hora_min, hora_max = valores
    elif len(valores) != 0:
        parser.error("La opción -s requiere exactamente dos horas (HHMMSS) o ninguna para usar valores por defecto.")

imp_report(
    records,
    intentos=args.attempts,
    fallidos=args.failed_attempts,
    sospechosos=hasattr(args, "suspicious_activity"),
    fBruta=args.brute_force,
    hora_min=hora_min,
    hora_max=hora_max,
    compromise=args.compromise,
    distributed=args.distributed,
    multi=args.multi_connections,
    geo=args.geo_connections,
    horary=args.out_horary_connections,
)
