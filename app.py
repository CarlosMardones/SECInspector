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
        
        # Guardar reportes de hallazgos en JSON (incluye comparación automática)
        report_file, comparison = self.portScanner.save_reports_to_json()
        if report_file:
            self.logger.info(f"Reporte de hallazgos guardado: {report_file}")
            
            # Mostrar resumen de comparación en logs
            self.portScanner.log_comparison_summary(comparison)
        else:
            self.logger.info("No hay hallazgos para guardar")
        
        self.logger.info("Aplicación finalizada.")
