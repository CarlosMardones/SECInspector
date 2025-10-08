import socket
import json
import os
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

        if self.logger:
            if status == "OK":
                #self.logger.info(message)
                pass
            else:
                self.logger.warning(message)
        else:
            print(message)