import socket
from typing import Optional, Tuple

try:
    import psutil
except Exception:  # psutil puede no estar instalado
    psutil = None  # type: ignore


class PortScanner:

    def __init__(self, logger=None):
        self.logger = logger
        if self.logger:
            self.logger.info("Escaneo de puertos inicializado")
        # Mapeo básico de puertos conocidos a servicios esperados y nombres de procesos comunes
        # Nota: En Windows muchos servicios corren bajo svchost.exe
        self.port_expected_processes = {
            22: {"sshd", "ssh.exe"},
            80: {"nginx", "apache2", "httpd", "iisexpress.exe", "w3wp.exe"},
            443: {"nginx", "apache2", "httpd", "iisexpress.exe", "w3wp.exe"},
            3306: {"mysqld"},
            5432: {"postgres", "postgres.exe"},
            27017: {"mongod"},
            # Puertos típicos Windows
            135: {"svchost.exe", "rpcss"},  # RPC Endpoint Mapper
            139: {"System"},
            445: {"System", "svchost.exe"},  # SMB
            3389: {"svchost.exe", "TermService"},  # RDP
            5985: {"svchost.exe"},  # WinRM HTTP
            5986: {"svchost.exe"},  # WinRM HTTPS
            5357: {"svchost.exe"},  # WSDAPI
        }
        self.generally_safe_process_names = {
            "svchost.exe", "System", "system", "w3wp.exe", "iisexpress.exe",
            "nginx", "apache2", "httpd", "postgres", "postgres.exe",
            "mysqld", "mongod", "node", "node.exe", "python", "python.exe"
        }

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
        if port in {135, 139, 445, 3389, 5985, 5986, 5357} and process_name is None:
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