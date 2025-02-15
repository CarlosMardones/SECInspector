from utils.logger import Logger
from config import Config
from scanner.portscanner import PortScanner


class App:
    """Clase principal que controla el flujo del programa."""
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.portScanner = PortScanner()

    def run(self):
        self.logger.log("Iniciando aplicación...")
        print(f"Configuración actual: {self.config.setting}")
        self.logger.log("Aplicación finalizada.")