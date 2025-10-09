from utils.logger import Logger
from config import Config
from scanner.port_scanner import PortScanner
from scanner.software_scanner import SoftwareScanner


class App:
    """Clase principal que controla el flujo del programa."""
    def __init__(self):
        self.config = Config()
        self.logger = Logger(name="SECInspector.App")
        self.port_scanner = PortScanner(logger=self.logger)
        self.software_scanner = SoftwareScanner(logger=self.logger)

    def run(self):
        self.logger.info("Iniciando aplicación...")
        self.logger.info(f"Configuración actual: {self.config.setting}")
        
        # Escaneo de puertos
        self.logger.info("=== INICIANDO ESCANEO DE PUERTOS ===")
        self.port_scanner.scan()
        
        # Guardar reportes de hallazgos en JSON (incluye comparación automática)
        report_file, comparison = self.port_scanner.save_reports_to_json()
        if report_file:
            self.logger.info(f"Reporte de puertos guardado: {report_file}")
            
            # Mostrar resumen de comparación en logs
            self.port_scanner.log_comparison_summary(comparison)
        else:
            self.logger.info("No hay hallazgos de puertos para guardar")
        
        # Escaneo de software
        self.logger.info("=== INICIANDO ESCANEO DE SOFTWARE ===")
        software_report_file = self.software_scanner.scan()
        if software_report_file:
            self.logger.info(f"Reporte de software guardado: {software_report_file}")
        else:
            self.logger.info("No se pudo generar reporte de software")
        
        self.logger.info("Aplicación finalizada.")
