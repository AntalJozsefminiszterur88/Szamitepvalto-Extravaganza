import configparser
import os

# A settings.ini fájl abszolút elérési útjának meghatározása
_config_path = os.path.join(os.path.dirname(__file__), 'settings.ini')

config = configparser.ConfigParser()
config.read(_config_path)

# Hálózati beállítások beolvasása alapértelmezett értékekkel
DEFAULT_PORT = config.getint('Network', 'DefaultPort', fallback=65432)

# Hardver beállítások beolvasása alapértelmezett értékekkel
PICO_SERIAL_PORT = config.get('Hardware', 'PicoSerialPort', fallback='COM7')
