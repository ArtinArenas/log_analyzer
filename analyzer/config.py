from datetime import time

# Configuración centralizada para detectores de autenticación.
# Ajustar estos valores según el entorno o la política de seguridad.

DEFAULT_HOUR_INFERIOR = time(0, 0, 0)
DEFAULT_HOUR_SUPERIOR = time(5, 0, 0)

RAPID_BRUTE_FORCE_THRESHOLD = 10
RAPID_BRUTE_FORCE_WINDOW_MINUTES = 1

PERSISTENT_BRUTE_FORCE_THRESHOLD = 30

POSSIBLE_COMPROMISE_THRESHOLD = 10

SPRAYING_USER_THRESHOLD = 3

# Ejemplo de configuración equivalente en un entorno externo:
# DEFAULT_HOUR_INFERIOR = time(0, 0, 0)
# DEFAULT_HOUR_SUPERIOR = time(5, 0, 0)
# RAPID_BRUTE_FORCE_THRESHOLD = 10
# RAPID_BRUTE_FORCE_WINDOW_MINUTES = 1


IPINFO_TOKEN = "your_ipinfo_token_here"  # Reemplaza con tu token de IPinfo