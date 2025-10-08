import socket
import json
import os
from datetime import datetime
from typing import Optional, Tuple, Dict, List

try:
    import psutil
except Exception:  # psutil puede no estar instalado
    psutil = None  # type: ignore


class PortScanner:

    def __init__(self, logger=None, config_file="port_config.json"):
        self.logger = logger
        if self.logger:
            self.logger.info("Escaneo de puertos inicializado")
        
        # Cargar configuración desde archivo JSON
        self.port_expected_processes: Dict[int, List[str]] = {}
        self.generally_safe_process_names: List[str] = []
        self.sensitive_ports: List[int] = []
        
        # Lista para almacenar reportes que requieren atención
        self.reports_to_save: List[Dict] = []
        
        self.load_config(config_file)

    def load_config(self, config_file: str) -> None:
        """Carga la configuración desde el archivo JSON."""
        try:
            # Buscar el archivo en el directorio actual y en el directorio del proyecto
            config_paths = [
                config_file,
                os.path.join(os.path.dirname(__file__), "..", config_file),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), config_file)
            ]
            
            config_path = None
            for path in config_paths:
                if os.path.exists(path):
                    config_path = path
                    break
            
            if not config_path:
                if self.logger:
                    self.logger.error(f"No se encontró el archivo de configuración: {config_file}")
                else:
                    print(f"Error: No se encontró el archivo de configuración: {config_file}")
                self._load_default_config()
                return
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Convertir claves string a int para puertos
            self.port_expected_processes = {
                int(port): processes 
                for port, processes in config.get("port_expected_processes", {}).items()
            }
            
            self.generally_safe_process_names = config.get("generally_safe_process_names", [])
            self.sensitive_ports = config.get("sensitive_ports", [])
            
            if self.logger:
                self.logger.info(f"Configuración cargada desde: {config_path}")
                self.logger.info(f"Puertos configurados: {len(self.port_expected_processes)}")
                
        except json.JSONDecodeError as e:
            if self.logger:
                self.logger.error(f"Error al parsear JSON: {e}")
            else:
                print(f"Error al parsear JSON: {e}")
            self._load_default_config()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error al cargar configuración: {e}")
            else:
                print(f"Error al cargar configuración: {e}")
            self._load_default_config()

    def _load_default_config(self) -> None:
        """Carga configuración por defecto si falla la carga del archivo."""
        if self.logger:
            self.logger.warning("Usando configuración por defecto")
        
        self.port_expected_processes = {
            22: ["sshd", "ssh.exe"],
            80: ["nginx", "apache2", "httpd", "iisexpress.exe", "w3wp.exe"],
            443: ["nginx", "apache2", "httpd", "iisexpress.exe", "w3wp.exe"],
            3306: ["mysqld"],
            5432: ["postgres", "postgres.exe"],
            27017: ["mongod"],
            135: ["svchost.exe", "rpcss"],
            139: ["System"],
            445: ["System", "svchost.exe"],
            3389: ["svchost.exe", "TermService"],
            5985: ["svchost.exe"],
            5986: ["svchost.exe"],
            5357: ["svchost.exe"]
        }
        
        self.generally_safe_process_names = [
            "svchost.exe", "System", "system", "w3wp.exe", "iisexpress.exe",
            "nginx", "apache2", "httpd", "postgres", "postgres.exe",
            "mysqld", "mongod", "node", "node.exe", "python", "python.exe"
        ]
        
        self.sensitive_ports = [135, 139, 445, 3389, 5985, 5986, 5357]

    def save_reports_to_json(self, output_dir: str = "reports") -> Tuple[str, Dict]:
        """Guarda los reportes (incluido si están vacíos) en un archivo JSON con timestamp."""
        current_findings: List[Dict] = list(self.reports_to_save)
        
        # Crear directorio de reportes si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"port_scan_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        # Realizar comparación con el último escaneo
        comparison = self.compare_with_last_scan(current_findings, output_dir)
        
        # Preparar datos del reporte
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(current_findings),
                "scanner_version": "1.0"
            },
            "findings": current_findings,
            "comparison_summary": comparison
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            if self.logger:
                self.logger.info(f"Reporte guardado en: {filepath}")
            else:
                print(f"Reporte guardado en: {filepath}")
            
            return filepath, comparison
            
        except Exception as e:
            error_msg = f"Error al guardar reporte: {e}"
            if self.logger:
                self.logger.error(error_msg)
            else:
                print(error_msg)
            return "", {}

    def load_last_report(self, reports_dir: str = "reports") -> Optional[Dict]:
        """Carga el último reporte JSON generado para comparación."""
        if not os.path.exists(reports_dir):
            return None
        
        try:
            # Buscar archivos de reporte ordenados por fecha
            report_files = [f for f in os.listdir(reports_dir) if f.startswith("port_scan_report_") and f.endswith(".json")]
            if not report_files:
                return None
            
            # Ordenar por nombre (que incluye timestamp)
            report_files.sort(reverse=True)
            latest_file = os.path.join(reports_dir, report_files[0])
            
            with open(latest_file, 'r', encoding='utf-8') as f:
                last_report = json.load(f)
            
            if self.logger:
                self.logger.info(f"Cargado último reporte para comparación: {latest_file}")
            
            return last_report
            
        except Exception as e:
            if self.logger:
                self.logger.warning(f"No se pudo cargar el último reporte: {e}")
            return None

    def compare_with_last_scan(self, current_findings: List[Dict], reports_dir: str = "reports") -> Dict:
        """Compara los hallazgos actuales con el último escaneo."""
        last_report = self.load_last_report(reports_dir)
        
        if not last_report:
            return {
                "comparison_available": False,
                "message": "No hay reportes previos para comparar"
            }
        
        last_findings = last_report.get("findings", [])
        last_scan_time = last_report.get("scan_info", {}).get("timestamp", "Desconocido")
        
        # Crear conjuntos para comparación
        current_ports = {finding["port"] for finding in current_findings}
        last_ports = {finding["port"] for finding in last_findings}
        
        # Encontrar diferencias
        new_ports = current_ports - last_ports
        removed_ports = last_ports - current_ports
        common_ports = current_ports & last_ports
        
        # Detectar cambios en puertos comunes
        changed_ports = []
        for port in common_ports:
            current_finding = next((f for f in current_findings if f["port"] == port), None)
            last_finding = next((f for f in last_findings if f["port"] == port), None)
            
            if current_finding and last_finding:
                # Comparar campos relevantes
                if (current_finding["service"] != last_finding["service"] or
                    current_finding["status"] != last_finding["status"] or
                    current_finding["pid"] != last_finding["pid"]):
                    changed_ports.append({
                        "port": port,
                        "current": current_finding,
                        "previous": last_finding
                    })
        
        comparison_result = {
            "comparison_available": True,
            "last_scan_time": last_scan_time,
            "summary": {
                "current_total": len(current_findings),
                "previous_total": len(last_findings),
                "new_ports": len(new_ports),
                "removed_ports": len(removed_ports),
                "changed_ports": len(changed_ports),
                "unchanged_ports": len(common_ports) - len(changed_ports)
            },
            "details": {
                "new_ports": list(new_ports),
                "removed_ports": list(removed_ports),
                "changed_ports": changed_ports
            }
        }
        
        return comparison_result

    def save_comparison_report(self, comparison: Dict, output_dir: str = "reports") -> str:
        """Guarda el reporte de comparación en un archivo JSON separado."""
        if not comparison.get("comparison_available"):
            return ""
        
        # Crear directorio si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"comparison_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(comparison, f, indent=2, ensure_ascii=False)
            
            if self.logger:
                self.logger.info(f"Reporte de comparación guardado: {filepath}")
            
            return filepath
            
        except Exception as e:
            error_msg = f"Error al guardar reporte de comparación: {e}"
            if self.logger:
                self.logger.error(error_msg)
            return ""

    def log_comparison_summary(self, comparison: Dict) -> None:
        """Muestra un resumen de la comparación en los logs."""
        if not comparison.get("comparison_available"):
            if self.logger:
                self.logger.info(comparison.get("message", "No hay comparación disponible"))
            return
        
        summary = comparison["summary"]
        
        if self.logger:
            self.logger.info("=== RESUMEN DE COMPARACIÓN ===")
            self.logger.info(f"Último escaneo: {comparison['last_scan_time']}")
            self.logger.info(f"Hallazgos actuales: {summary['current_total']}")
            self.logger.info(f"Hallazgos anteriores: {summary['previous_total']}")
            
            if summary['new_ports'] > 0:
                self.logger.warning(f"⚠️  PUERTOS NUEVOS: {summary['new_ports']} - {comparison['details']['new_ports']}")
            
            if summary['removed_ports'] > 0:
                self.logger.info(f"✅ PUERTOS REMOVIDOS: {summary['removed_ports']} - {comparison['details']['removed_ports']}")
            
            if summary['changed_ports'] > 0:
                self.logger.warning(f"🔄 PUERTOS MODIFICADOS: {summary['changed_ports']}")
                for change in comparison['details']['changed_ports']:
                    port = change['port']
                    current = change['current']
                    previous = change['previous']
                    self.logger.warning(f"  Puerto {port}: {previous['service']}→{current['service']} | {previous['status']}→{current['status']}")
            
            if summary['unchanged_ports'] > 0:
                self.logger.info(f"📌 PUERTOS SIN CAMBIOS: {summary['unchanged_ports']}")
        else:
            # Fallback para cuando no hay logger
            print("=== RESUMEN DE COMPARACIÓN ===")
            print(f"Último escaneo: {comparison['last_scan_time']}")
            print(f"Hallazgos actuales: {summary['current_total']}")
            print(f"Hallazgos anteriores: {summary['previous_total']}")
            
            if summary['new_ports'] > 0:
                print(f"⚠️  PUERTOS NUEVOS: {summary['new_ports']} - {comparison['details']['new_ports']}")
            
            if summary['removed_ports'] > 0:
                print(f"✅ PUERTOS REMOVIDOS: {summary['removed_ports']} - {comparison['details']['removed_ports']}")
            
            if summary['changed_ports'] > 0:
                print(f"🔄 PUERTOS MODIFICADOS: {summary['changed_ports']}")

    def scan(self):
        if psutil is None:
            msg = "psutil no está disponible. Instala con 'pip install psutil' para escaneo de procesos."
            if self.logger:
                self.logger.error(msg)
            else:
                print(msg)
            # Fallback mínimo: tabla estática de servicios conocidos por número de puerto
            for i in range(1, 65535):
                info = self.get_service(i)
                if info != "Desconocido":
                    status, reason = self.classify_without_process(i, info)
                    self._report(i, None, info, status, reason, laddr=None)
            return

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            msg = f"No se pudieron obtener conexiones (requiere privilegios). Detalle: {exc}"
            if self.logger:
                self.logger.error(msg)
            else:
                print(msg)
            return

        # Filtrar puertos en LISTEN
        listening = [c for c in connections if getattr(c, "status", "") == psutil.CONN_LISTEN]

        # Mapear por puerto local
        for conn in listening:
            laddr = getattr(conn, "laddr", None)
            port = getattr(laddr, "port", None) if laddr else None
            pid = getattr(conn, "pid", None)
            if port is None:
                continue

            proc_name: Optional[str] = None
            try:
                if pid:
                    p = psutil.Process(pid)
                    proc_name = p.name()
            except Exception:
                proc_name = None

            known_service = self.get_service(port)
            status, reason = self.classify(port, proc_name, known_service)
            self._report(port, pid, known_service, status, reason, laddr=laddr)


    def get_service(self, port):
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Desconocido"

    def classify(self, port: int, process_name: Optional[str], known_service: str) -> Tuple[str, str]:
        # Regla 1: Puertos bien conocidos con proceso esperado
        expected = self.port_expected_processes.get(port)
        if expected and process_name and process_name in expected:
            return ("OK", f"Puerto {port} coincide con proceso esperado '{process_name}' para {known_service}")

        # Regla 2: Proceso generalmente seguro en puerto conocido (o servicio conocido)
        if process_name and process_name in self.generally_safe_process_names and known_service != "Desconocido":
            return ("OK", f"Proceso '{process_name}' y servicio {known_service} son habituales")

        # Regla 3: Puertos administrativos Windows sin nombre de proceso (posible falta de privilegios)
        if port in self.sensitive_ports and process_name is None:
            return ("REVISAR", "No se pudo determinar el proceso para puerto sensible de Windows; comprobar privilegios")

        # Regla 4: Servicio desconocido o proceso no esperado
        if known_service == "Desconocido":
            if process_name:
                return ("REVISAR", f"Servicio desconocido en puerto {port} con proceso '{process_name}'")
            return ("REVISAR", f"Servicio desconocido en puerto {port} (proceso no determinado)")

        # Regla 5: Servicio conocido pero proceso no esperado
        if expected and process_name and process_name not in expected:
            return ("REVISAR", f"Se esperaba {expected} para puerto {port}, pero se encontró '{process_name}'")

        # Regla 6: Sin reglas específicas, marcar como revisar si el proceso es desconocido
        if not process_name:
            return ("REVISAR", f"Servicio {known_service} en puerto {port} con proceso no determinado")

        # Por defecto OK si no hay señales negativas
        return ("OK", f"Servicio {known_service} en puerto {port} con proceso '{process_name}'")

    def classify_without_process(self, port: int, known_service: str) -> Tuple[str, str]:
        if known_service == "Desconocido":
            return ("REVISAR", f"Servicio desconocido en puerto {port}")
        if port in self.port_expected_processes:
            return ("REVISAR", f"No se pudo validar proceso para puerto {port} ({known_service})")
        return ("OK", f"Servicio {known_service} en puerto {port}")

    def _report(self, port: int, pid: Optional[int], known_service: str, status: str, reason: str, laddr=None) -> None:
        addr_str = None
        try:
            if laddr:
                addr_str = f"{getattr(laddr, 'ip', '')}:{getattr(laddr, 'port', '')}" if hasattr(laddr, 'ip') else f"{laddr}"
        except Exception:
            addr_str = None

        message = f"PORT {port} | SERVICIO {known_service} | ESTADO {status} | PID {pid} | {reason}"
        if addr_str:
            message = f"{message} | LADDR {addr_str}"

        # Almacenar reportes que requieren atención (WARNING/ERROR)
        if status in ["REVISAR", "ERROR"]:
            report_entry = {
                "port": port,
                "service": known_service,
                "status": status,
                "pid": pid,
                "reason": reason,
                "local_address": addr_str,
                "timestamp": datetime.now().isoformat()
            }
            self.reports_to_save.append(report_entry)

        if self.logger:
            if status == "OK":
                #self.logger.info(message)
                pass
            else:
                self.logger.warning(message)
        else:
            print(message)