from detector import (
    attempts_for_ip, 
    #brute_force_for_ip, 
    failed_attempts_for_ip, 
    public_ips, 
    suspicious_activity_by_hour, 
    detect_brute_force_by_ip,
    detect_distributed_brute_force,
    detect_possible_compromise,
    multi_connections,
    geo_connections,
    out_horary_connections,)
from utils import count_registros, count_registros_failed, get_first_record_date, get_last_record_date
from types import SimpleNamespace

#Resumen: muestra cantidad logins, cantidad de logins fallidos, fecha del primer registro, fecha del ultimo registro.
def report_summary(alerts):
    total_attempts = count_registros(alerts)
    total_failed_attempts = count_registros_failed(alerts)
    first_record_date = get_first_record_date(alerts)
    last_record_date = get_last_record_date(alerts)
    
    return SimpleNamespace(
        total_attempts=total_attempts,
        total_failed_attempts=total_failed_attempts,
        first_record_date=first_record_date,
        last_record_date=last_record_date,
    )





def _print_section(title):
    print(f"\n{'=' * 64}\n{title}\n{'-' * 64}")


def _print_results(results, printer):
    if not results:
        print("Sin resultados.")
        return
    for index, result in enumerate(results, start=1):
        print(f"\n[{index}]")
        printer(result)


def imp_report(
    alerts,
    intentos=False,
    fallidos=False,
    sospechosos=False,
    fBruta=False,
    hora_min=None,
    hora_max=None,
    compromise=False,
    distributed=False,
    multi=False,
    geo=False,
    horary=False,
):
    summary = report_summary(alerts)
    print("\n" + "=" * 64)
    print("ANALISIS DE LOGS")
    print("=" * 64)
    print(f"Registros analizados : {summary.total_attempts}")
    print(f"Intentos fallidos    : {summary.total_failed_attempts}")
    print(f"Primer registro      : {summary.first_record_date}")
    print(f"Ultimo registro      : {summary.last_record_date}")

    if intentos:
        _print_section("INTENTOS POR IP")
        _print_results(attempts_for_ip(alerts), lambda res: print(
            f"IP: {res.ip_address}\n"
            f"Intentos: {res.attempts}\n"
            f"Usuarios: {', '.join(res.user_id) or 'N/A'}\n"
            f"Severidad: {res.severity}"
        ))

    if fallidos:
        _print_section("INTENTOS FALLIDOS POR IP")
        _print_results(failed_attempts_for_ip(alerts), lambda res: print(
            f"IP: {res.ip_address}\n"
            f"Intentos fallidos: {res.attempts}\n"
            f"Usuarios: {', '.join(res.user_id) or 'N/A'}\n"
            f"Severidad: {res.severity}"
        ))

    if sospechosos:
        _print_section("ACTIVIDAD SOSPECHOSA POR HORARIO")
        _print_results(suspicious_activity_by_hour(alerts, hora_min, hora_max), lambda res: print(
            f"IP: {res.ip_address}\n"
            f"Intentos en el rango: {res.attempts}\n"
            f"Usuarios: {', '.join(res.user_id) or 'N/A'}\n"
            f"Severidad: {res.severity}"
        ))

    if fBruta:
        _print_section("FUERZA BRUTA POR IP")
        _print_results(detect_brute_force_by_ip(alerts), lambda res: print(
            f"IP: {res.ip_address}\n"
            f"Ataque rapido: {res.rapid}\n"
            f"Ataque persistente: {res.persistent}\n"
            f"Ataque spraying: {res.spraying}"
        ))

    if compromise:
        _print_section("POSIBLES USUARIOS COMPROMETIDOS")
        _print_results(detect_possible_compromise(alerts), lambda res: print(
            f"Usuario: {res['user']}\n"
            f"Intentos fallidos: {res['failedAttempts']}\n"
            f"Comprometido: {res['compromise']}"
        ))

    if distributed:
        _print_section("FUERZA BRUTA DISTRIBUIDA")
        _print_results(detect_distributed_brute_force(alerts), lambda res: print(
            f"Usuario: {res['user']}\n"
            f"Numero de IPs: {res['numberOfIPs']}\n"
            f"IPs: {', '.join(res['ips'])}"
        ))

    if multi:
        _print_section("CONEXIONES MULTIPLES")
        _print_results(multi_connections(alerts, window_minutes=5), lambda res: print(
            f"Usuario: {res['user']}\n"
            f"IPs: {', '.join(res['ips'])}\n"
            f"Numero de IPs: {res['numberOfIPs']}\n"
            f"Inicio: {res['start']}\n"
            f"Fin: {res['end']}"
        ))

    if geo:
        _print_section("CONEXIONES GEOGRAFICAS")
        _print_results(geo_connections(alerts, window_minutes=5), lambda res: print(
            f"Usuario: {res['user']}\n"
            f"IPs: {', '.join(res['ips'])}\n"
            f"Paises: {', '.join(res['countries'])}\n"
            f"Numero de paises: {res['numberOfCountries']}\n"
            f"Inicio: {res['start']}\n"
            f"Fin: {res['end']}"
        ))

    if horary:
        _print_section("CONEXIONES FUERA DEL HORARIO HABITUAL")
        _print_results(out_horary_connections(alerts), lambda res: print(
            f"Usuario: {res['user']}\n"
            f"IP: {res['ip']}\n"
            f"Hora: {res['hour']}\n"
            f"Limite inferior: {res['lower_bound']}\n"
            f"Limite superior: {res['upper_bound']}"
        ))

    