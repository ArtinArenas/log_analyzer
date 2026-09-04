# log_analyzer

Herramienta de línea de comandos para analizar logs de autenticación SSH y detectar actividad sospechosa, ataques de fuerza bruta y conexiones anómalas.

## Instalación

Desde la raíz del proyecto:

```powershell
python -m pip install -e .
```

Esto instala las dependencias y crea el comando `log-analyzer`. Si la carpeta de scripts de Python no está en el `PATH`, se puede ejecutar directamente:

```powershell
python analyzer\main.py --help
```

## Uso

El archivo de log se indica como último argumento para todas las opciones de análisis:

```powershell
python analyzer\main.py [flags] archivo.log
```

Ejemplos:

```powershell
python analyzer\main.py -a activity.log
python analyzer\main.py -f -b activity.log
python analyzer\main.py -a -f -b -c -d -m -g -o activity.log
python analyzer\main.py -s 000000 050000 activity.log
python analyzer\main.py -p -a activity.log
```

También se puede usar el comando instalado:

```powershell
log-analyzer -a activity.log
```

## Flags de análisis

| Flag | Equivalente largo | Función |
| --- | --- | --- |
| `-a` | `--attempts` | Muestra todos los intentos agrupados por IP, con usuarios y severidad. |
| `-f` | `--failed_attempts` | Muestra únicamente los intentos fallidos agrupados por IP. |
| `-b` | `--brute_force` | Detecta fuerza bruta rápida, persistente o por spraying. |
| `-c` | `--compromise` | Detecta posibles usuarios comprometidos por fallos seguidos de un éxito. |
| `-d` | `--distributed` | Detecta un mismo usuario atacado desde varias IPs. |
| `-m` | `--multi_connections` | Detecta conexiones exitosas de un usuario desde varias IPs en una ventana de tiempo. |
| `-g` | `--geo_connections` | Detecta conexiones exitosas de un usuario desde distintos países. Requiere configurar IPinfo. |
| `-o` | `--out_horary_connections` | Detecta conexiones exitosas fuera del horario habitual del usuario. |
| `-s` | `--suspicious_activity` | Filtra la actividad por rango horario `HHMMSS HHMMSS`. |
| `-p` | `--public_ips` | Filtra el análisis para conservar únicamente eventos originados en IPs públicas. |
| | `--update` | Descarga o actualiza la base de datos GeoIP de IPinfo. |

Se pueden combinar varias flags en una misma ejecución. El archivo de log es obligatorio para las opciones de análisis. `--update` es la única operación que puede ejecutarse sin archivo:

```powershell
python analyzer\main.py --update
```

## IPs públicas y geolocalización

La flag `-p` excluye del resultado las IPs privadas, de loopback y link-local. Por ejemplo:

```powershell
python analyzer\main.py -p -a activity.log
```

Para utilizar `geo_connections` (`-g`) es necesario:

1. Crear una cuenta en [IPinfo](https://ipinfo.io/).
2. Obtener un token de acceso.
3. Cargar el token en `analyzer/config.py`:

   ```text
   IPINFO_TOKEN=tu_token
   ```
4. Ejecutar la actualización de la base de datos:

   ```powershell
   python analyzer\main.py --update
   ```

5. Ejecutar el análisis geográfico:

   ```powershell
   python analyzer\main.py -g archivo.log
   ```

Es recomendable ejecutar `--update` cada cierto tiempo para mantener actualizada la información geográfica de las IPs. El token no debe compartirse ni subirse al repositorio.

## Formatos de entrada

### OpenSSH

El parser reconoce líneas como:

```text
ago 01 14:16:02 debian sshd[2893]: Failed password for invalid user root from 192.168.1.37 port 40340 ssh2
```

Normaliza el resultado a `LOGIN_SUCCESS` o `LOGIN_FAILED`, y registra usuario, IP, método, puerto, fecha, hora y resultado original.

### Formato de actividad

También reconoce líneas con el formato:

```text
2026-07-20 081532 LOGIN_SUCCESS user=juan ip=192.168.1.15
```

## Funciones principales

### `parser.py`

- `parse_log(path)`: selecciona el parser según el contenido del archivo.
- `example_parser(path)`: procesa el formato de actividad normalizado.
- `openSsh_parser(path)`: procesa logs de OpenSSH.

### `detector.py`

- `attempts_for_ip(events)`: agrupa todos los eventos por IP.
- `failed_attempts_for_ip(events)`: agrupa únicamente fallos por IP.
- `suspicious_activity_by_hour(events, hour_inferior, hour_superior)`: filtra eventos por horario.
- `detect_rapid_brute_force(attempts)`: detecta muchos fallos en una ventana corta.
- `detect_persistent_brute_force(attempts)`: detecta fallos consecutivos persistentes.
- `detect_possible_compromise(attempts)`: detecta fallos seguidos de un acceso exitoso.
- `detect_spraying_brute_force(attempts)`: detecta intentos contra varios usuarios.
- `detect_distributed_brute_force(events)`: detecta ataques contra un usuario desde varias IPs.
- `detect_brute_force_by_ip(events)`: combina los detectores de fuerza bruta por IP.
- `multi_connections(events, window_minutes=5)`: detecta conexiones multi-IP.
- `geo_connections(events, window_minutes=5)`: detecta conexiones desde distintos países usando IPinfo.
- `out_horary_connections(events)`: detecta accesos exitosos fuera del horario habitual.
- `detect_anomalias(events, window_minutes=5)`: ejecuta los tres detectores de anomalías.

### `models.py`

- `normalize_action(action, result, method)`: normaliza la acción de autenticación.
- `normalize_outcome(result, action)`: normaliza el resultado a `success`, `failure` o `unknown`.
- `classify_event(event)`: clasifica un evento usando su resultado normalizado.

### `utils.py`

- `descargar_base_datos()`: descarga la base GeoIP usando `IPINFO_TOKEN`.
- `public_ips(events)`: filtra eventos que provienen de IPs públicas.
- `count_registros(events)`: cuenta registros.
- `count_registros_failed(events)`: cuenta registros fallidos.
- `get_first_record_date(events)`: obtiene la fecha del primer registro.
- `get_last_record_date(events)`: obtiene la fecha del último registro.

## Configuración

Los umbrales se encuentran en `analyzer/config.py`:

```python
DEFAULT_HOUR_INFERIOR = time(0, 0, 0)
DEFAULT_HOUR_SUPERIOR = time(5, 0, 0)
RAPID_BRUTE_FORCE_THRESHOLD = 10
RAPID_BRUTE_FORCE_WINDOW_MINUTES = 1
PERSISTENT_BRUTE_FORCE_THRESHOLD = 30
POSSIBLE_COMPROMISE_THRESHOLD = 10
SPRAYING_USER_THRESHOLD = 3
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Estructura

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
└── README.md

```
