# log_analyzer

Analyzer de logs orientado a detectar autenticaciones sospechosas, fuerza bruta y anomalías de acceso en sistemas SSH y archivos de actividad.

## Objetivo

El proyecto procesa registros de acceso, normaliza eventos a un formato consistente y aplica detectores para identificar:

- intentos fallidos repetidos por IP
- fuerza bruta por ventana de tiempo
- patrones sospechosos por horario
- posible compromiso de cuenta
- ataques distribuidos o multi-IP
- anomalías de acceso en horario no habitual

## Arquitectura

El flujo principal es:

1. lectura del archivo de logs
2. selección del parser apropiado
3. normalización del evento con `action`, `result` y `outcome`
4. agregación por IP o usuario
5. ejecución de detectores
6. salida de resultados estructurados

## Modelos principales

### Event

Representa cada evento autenticado leído del log.

Atributos:
- `timestamp`: fecha ISO
- `hour`: hora en formato `HHMMSS`
- `action`: acción normalizada, por ejemplo `LOGIN_SUCCESS`
- `user_id`: lista con el usuario involucrado
- `ip_address`: dirección IP origen
- `attempts`: contador del evento
- `source`: origen del parser (`example`, `openssh`)
- `result`: resultado bruto o normalizado
- `method`: método de autenticación (`password`, `publickey`)
- `port`: puerto asociado
- `raw`: línea original del log
- `outcome`: `success`, `failure` o `unknown`

### Detail

Versión más simple para eventos ya normalizados en una capa de dominio ligera.

### DetalleIntentos

Resumen agregado por IP.

Atributos:
- `ip_address`
- `attempts`
- `attempts_failed`
- `failed_user_ids`
- `attempts_success`
- `successful_user_ids`

### DetalleIntentosHora

Extensión de `DetalleIntentos` para análisis por rango horario.

### DetalleBruteForce

Objeto auxiliar para un usuario dentro del análisis de fuerza bruta.

### BruteForceResult

Resultado consolidado por IP.

Atributos:
- `ip_address`
- `rapid`
- `persistent`
- `compromise`
- `spraying`

### Alert

Estructura de salida utilizada por utilidades de reporte.

## Normalización de resultados

La parte central del proyecto es convertir todas las señales a un formato uniforme:

- `action` → `LOGIN_SUCCESS` o `LOGIN_FAILED`
- `outcome` → `success` o `failure`
- `result` → valor bruto de origen o valor normalizado

Esto evita que cada detector dependa de cadenas como `Accepted`, `Failed`, `LOGIN_SUCCESS`, `LOGIN_FAILED` y similares.

## Funciones clave

### parser.py

#### parse_log(path)

Selecciona el parser correcto según el contenido del archivo.

#### example_parser(path)

Parsea entradas tipo:

```text
2026-07-20 081532 LOGIN_SUCCESS user=juan ip=192.168.1.15
```

#### openSsh_parser(path)

Parsea logs de OpenSSH, por ejemplo:

```text
ago 01 14:16:02 debian sshd[2893]: Failed password for invalid user root from 192.168.1.37 port 40340 ssh2
```

### detector.py

#### attempts_for_ip(events)

Cuenta eventos por IP y devuelve una lista con:

- IP
- cantidad total de intentos
- usuarios implicados
- severidad calculada

#### failed_attempts_for_ip(events)

Similar a la anterior, pero solo incluye eventos con `outcome == "failure"`.

#### suspicious_activity_by_hour(events, hour_inferior=None, hour_superior=None)

Filtra eventos según un rango horario y devuelve conteos por hora.

#### brute_force_for_ip(events, threshold=3)

Detecta IPs con fallos repetidos por encima de un umbral.

#### detect_rapid_brute_force(attempts)

Detecta un conjunto de fallos dentro de una ventana muy corta.

#### detect_persistent_brute_force(attempts)

Detecta una racha prolongada de fallos consecutivos.

#### detect_possible_compromise(attempts)

Marca usuarios que tienen varios fallos antes de un éxito.

#### detect_spraying_brute_force(attempts)

Detecta que una misma IP intenta autenticarse contra múltiples usuarios distintos.

#### detect_distributed_brute_force(events)

Identifica usuarios que fallan desde varias IPs distintas.

#### detect_anomalias(events, window_minutes=5, work_start=8, work_end=18)

Agrupa tres controles:

- `multi_connections`: varios accesos exitosos de un mismo usuario desde distintas IPs
- `geo_connections`: variante de accesos distribuidos
- `out_horary_connections`: accesos fuera del horario laboral normal

## Uso desde CLI

El punto de entrada es `analyzer/main.py`.

```bash
python analyzer/main.py --attempts activity.log
python analyzer/main.py --failed_attempts activity.log
python analyzer/main.py --brute_force activity.log
python analyzer/main.py --suspicious_activity 000000 050000 activity.log
python analyzer/main.py --public_ips activity.log
```

## Configuración

Los parámetros de seguridad y detección quedan centralizados en `analyzer/config.py`.

Ejemplo:

```python
DEFAULT_HOUR_INFERIOR = time(0, 0, 0)
DEFAULT_HOUR_SUPERIOR = time(5, 0, 0)
RAPID_BRUTE_FORCE_THRESHOLD = 10
RAPID_BRUTE_FORCE_WINDOW_MINUTES = 1
PERSISTENT_BRUTE_FORCE_THRESHOLD = 30
POSSIBLE_COMPROMISE_THRESHOLD = 10
SPRAYING_USER_THRESHOLD = 3
```

## Estructura del proyecto

```text
log_analyzer/
├── analyzer/
│   ├── config.py
│   ├── detector.py
│   ├── main.py
│   ├── models.py
│   ├── parser.py
│   ├── reports.py
│   └── utils.py
├── tests/
│   ├── test_detector.py
│   └── test_parser.py
├── README.md
└── activity.log
```

## Consideraciones

- El proyecto está centrado en autenticación y seguridad de acceso.
- El parser normaliza eventos para que los detectores no dependan de cadenas literales sueltas.
- La clase `Event` es la fuente de verdad para el análisis, mientras que `Detail` funciona como capa conceptual compatible y extensible.
