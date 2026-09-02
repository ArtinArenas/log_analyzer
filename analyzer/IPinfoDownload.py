import os
import urllib.request
from dotenv import load_dotenv

load_dotenv()

# El usuario debe configurar su token gratuito de IPinfo en su entorno
TOKEN = os.getenv("IPINFO_TOKEN")
DB_NAME = "ipinfo_lite.mmdb"

def descargar_base_datos():
    if not TOKEN:
        print("❌ Error: Necesitas configurar la variable de entorno IPINFO_TOKEN.")
        return False
        
    # URL oficial de descarga directa para el formato MMDB
    url = f"https://ipinfo.io/data/ipinfo_lite.mmdb?token={TOKEN}"
    
    print("⏳ Descargando la base de datos de IPinfo actualizada...")
    try:
        urllib.request.urlretrieve(url, DB_NAME)
        print("✅ Base de datos descargada con éxito.")
        return True
    except Exception as e:
        print(f"❌ Error al descargar: {e}")
        return False

# Ejecutar esto la primera vez o mediante un flag '--update'
if not os.path.exists(DB_NAME):
    descargar_base_datos()
