from utils.logger import Logger
from config import Config
from scanner.portscanner import PortScanner


class App:
    """Clase principal que controla el flujo del programa."""
    def __init__(self):
        self.config = Config()
        self.logger = Logger(name="SECInspector.App")
        self.portScanner = PortScanner(logger=self.logger)

    def run(self):
        self.logger.info("Iniciando aplicación...")
        self.logger.info(f"Configuración actual: {self.config.setting}")
        self.logger.info("Inicio scaneo de puertos")
        self.portScanner.scan()
        self.logger.info("Aplicación finalizada.")
