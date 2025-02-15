from utils.logger import Logger
from utils.config import Config


class App:
    """Clase principal que controla el flujo del programa."""
    def __init__(self):
        self.config = Config()
        self.logger = Logger()

    def run(self):
        self.logger.log("Iniciando aplicación...")
        print(f"Configuración actual: {self.config.setting}")
        self.logger.log("Aplicación finalizada.")