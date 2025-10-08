import json
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
import winreg
import platform

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

class SoftwareScanner:
    """Escáner de software instalado para identificar aplicaciones potencialmente peligrosas."""
    
    def __init__(self, logger=None, config_file="software_config.json"):
        self.logger = logger
        if self.logger:
            self.logger.info("SoftwareScanner inicializado")
        
        # Cargar configuración de software peligroso
        self.dangerous_software: Dict[str, Dict] = {}
        self.suspicious_keywords: List[str] = []
        self.trusted_publishers: Set[str] = set()
        self.known_good_software: Set[str] = set()
        
        self.load_config(config_file)
        
        # Inicializar WMI si está disponible
        self.wmi_conn = None
        if WMI_AVAILABLE and platform.system() == "Windows":
            try:
                self.wmi_conn = wmi.WMI()
                if self.logger:
                    self.logger.info("WMI inicializado correctamente")
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"No se pudo inicializar WMI: {e}")
                self.wmi_conn = None

    def load_config(self, config_file: str) -> None:
        """Carga la configuración de software desde archivo JSON."""
        try:
            # Buscar el archivo en múltiples ubicaciones
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
                self._load_default_config()
                return
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.dangerous_software = config.get("dangerous_software", {})
            self.suspicious_keywords = config.get("suspicious_keywords", [])
            self.trusted_publishers = set(config.get("trusted_publishers", []))
            self.known_good_software = set(config.get("known_good_software", []))
            
            if self.logger:
                self.logger.info(f"Configuración de software cargada desde: {config_path}")
                self.logger.info(f"Software peligroso conocido: {len(self.dangerous_software)}")
                self.logger.info(f"Editores de confianza: {len(self.trusted_publishers)}")
                
        except json.JSONDecodeError as e:
            if self.logger:
                self.logger.error(f"Error al parsear JSON de configuración: {e}")
            self._load_default_config()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error al cargar configuración de software: {e}")
            self._load_default_config()

    def _load_default_config(self) -> None:
        """Carga configuración por defecto de software peligroso."""
        if self.logger:
            self.logger.warning("Usando configuración por defecto de software")
        
        # Software conocido como peligroso
        self.dangerous_software = {
            "tor": {"risk_level": "HIGH", "category": "privacy_tool", "description": "Navegador Tor"},
            "proxy": {"risk_level": "MEDIUM", "category": "proxy", "description": "Software proxy"},
            "vpn": {"risk_level": "MEDIUM", "category": "vpn", "description": "Cliente VPN"},
            "keylogger": {"risk_level": "CRITICAL", "category": "malware", "description": "Keylogger"},
            "backdoor": {"risk_level": "CRITICAL", "category": "malware", "description": "Backdoor"},
            "trojan": {"risk_level": "CRITICAL", "category": "malware", "description": "Trojan"},
            "virus": {"risk_level": "CRITICAL", "category": "malware", "description": "Virus"},
            "crack": {"risk_level": "HIGH", "category": "pirate", "description": "Software crackeado"},
            "pirate": {"risk_level": "HIGH", "category": "pirate", "description": "Software pirata"},
            "hack": {"risk_level": "HIGH", "category": "hack_tool", "description": "Herramienta de hacking"},
            "exploit": {"risk_level": "HIGH", "category": "hack_tool", "description": "Exploit tool"}
        }
        
        # Palabras clave sospechosas
        self.suspicious_keywords = [
            "crack", "keygen", "patch", "loader", "injector", "bypass", 
            "hack", "cheat", "trainer", "exploit", "backdoor", "trojan",
            "virus", "malware", "keylogger", "spy", "stealer", "botnet"
        ]
        
        # Editores de confianza conocidos
        self.trusted_publishers = {
            "Microsoft Corporation", "Google LLC", "Mozilla Foundation",
            "Adobe Systems Incorporated", "Oracle Corporation", "Apple Inc.",
            "JetBrains s.r.o.", "GitHub, Inc.", "Canonical Ltd."
        }
        
        # Software conocido como bueno
        self.known_good_software = {
            "Microsoft Visual Studio", "Google Chrome", "Mozilla Firefox",
            "Adobe Acrobat", "Oracle Java", "Notepad++", "VLC Media Player",
            "7-Zip", "WinRAR", "Steam", "Discord", "Spotify"
        }

    def scan_installed_software(self) -> List[Dict]:
        """Escanea el software instalado en el sistema."""
        if self.logger:
            self.logger.info("Iniciando escaneo de software instalado...")
        
        installed_software = []
        
        # Método 1: Registro de Windows (32-bit y 64-bit)
        installed_software.extend(self._scan_registry_software())
        
        # Método 2: WMI (Windows Management Instrumentation)
        if self.wmi_conn:
            installed_software.extend(self._scan_wmi_software())
        
        # Método 3: PowerShell Get-WmiObject (fallback)
        installed_software.extend(self._scan_powershell_software())
        
        # Eliminar duplicados
        unique_software = self._deduplicate_software(installed_software)
        
        if self.logger:
            self.logger.info(f"Encontrados {len(unique_software)} programas instalados")
        
        return unique_software

    def _scan_registry_software(self) -> List[Dict]:
        """Escanea software instalado desde el registro de Windows."""
        software_list = []
        
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        for hkey, path in registry_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                software_info = self._extract_registry_software_info(subkey)
                                if software_info:
                                    software_list.append(software_info)
                        except (OSError, ValueError):
                            continue
            except OSError:
                continue
        
        return software_list

    def _extract_registry_software_info(self, subkey) -> Optional[Dict]:
        """Extrae información de software desde una clave del registro."""
        try:
            name = self._get_registry_value(subkey, "DisplayName")
            if not name:
                return None
            
            version = self._get_registry_value(subkey, "DisplayVersion")
            publisher = self._get_registry_value(subkey, "Publisher")
            install_date = self._get_registry_value(subkey, "InstallDate")
            install_location = self._get_registry_value(subkey, "InstallLocation")
            
            return {
                "name": name,
                "version": version or "Desconocida",
                "publisher": publisher or "Desconocido",
                "install_date": install_date,
                "install_location": install_location,
                "source": "registry"
            }
        except Exception:
            return None

    def _get_registry_value(self, key, value_name: str) -> Optional[str]:
        """Obtiene un valor del registro de Windows."""
        try:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value) if value else None
        except OSError:
            return None

    def _scan_wmi_software(self) -> List[Dict]:
        """Escanea software usando WMI."""
        software_list = []
        
        try:
            for product in self.wmi_conn.Win32_Product():
                if product.Name:
                    software_info = {
                        "name": product.Name,
                        "version": product.Version or "Desconocida",
                        "publisher": product.Vendor or "Desconocido",
                        "install_date": None,
                        "install_location": product.InstallLocation,
                        "source": "wmi"
                    }
                    software_list.append(software_info)
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Error en escaneo WMI: {e}")
        
        return software_list

    def _scan_powershell_software(self) -> List[Dict]:
        """Escanea software usando PowerShell como fallback."""
        software_list = []
        
        try:
            # Comando PowerShell para obtener software instalado
            cmd = [
                "powershell", "-Command",
                "Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallLocation | ConvertTo-Json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                import json
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            if item.get("Name"):
                                software_info = {
                                    "name": item["Name"],
                                    "version": item.get("Version") or "Desconocida",
                                    "publisher": item.get("Vendor") or "Desconocido",
                                    "install_date": None,
                                    "install_location": item.get("InstallLocation"),
                                    "source": "powershell"
                                }
                                software_list.append(software_info)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Error en escaneo PowerShell: {e}")
        
        return software_list

    def _deduplicate_software(self, software_list: List[Dict]) -> List[Dict]:
        """Elimina software duplicado basándose en el nombre."""
        seen_names = set()
        unique_software = []
        
        for software in software_list:
            name_lower = software["name"].lower().strip()
            if name_lower not in seen_names:
                seen_names.add(name_lower)
                unique_software.append(software)
        
        return unique_software

    def analyze_software_risk(self, software_list: List[Dict]) -> List[Dict]:
        """Analiza el riesgo de cada software instalado."""
        analyzed_software = []
        
        for software in software_list:
            risk_analysis = self._analyze_single_software(software)
            software_with_risk = {**software, **risk_analysis}
            analyzed_software.append(software_with_risk)
        
        return analyzed_software

    def _analyze_single_software(self, software: Dict) -> Dict:
        """Analiza el riesgo de un software individual."""
        name = software["name"].lower()
        publisher = software.get("publisher", "").lower()
        
        # Verificar si es software conocido como peligroso
        for dangerous_name, info in self.dangerous_software.items():
            if dangerous_name in name:
                return {
                    "risk_level": info["risk_level"],
                    "risk_category": info["category"],
                    "risk_description": info["description"],
                    "risk_reason": f"Software conocido como peligroso: {dangerous_name}",
                    "needs_review": True
                }
        
        # Verificar palabras clave sospechosas
        for keyword in self.suspicious_keywords:
            if keyword in name:
                return {
                    "risk_level": "HIGH",
                    "risk_category": "suspicious_keyword",
                    "risk_description": f"Contiene palabra clave sospechosa: {keyword}",
                    "risk_reason": f"Palabra clave '{keyword}' detectada en el nombre",
                    "needs_review": True
                }
        
        # Verificar si es software conocido como bueno
        for good_software in self.known_good_software:
            if good_software.lower() in name:
                return {
                    "risk_level": "LOW",
                    "risk_category": "known_good",
                    "risk_description": "Software conocido como seguro",
                    "risk_reason": f"Software conocido y confiable: {good_software}",
                    "needs_review": False
                }
        
        # Verificar editor de confianza
        for trusted_publisher in self.trusted_publishers:
            if trusted_publisher.lower() in publisher:
                return {
                    "risk_level": "LOW",
                    "risk_category": "trusted_publisher",
                    "risk_description": "Publicado por editor de confianza",
                    "risk_reason": f"Editor de confianza: {trusted_publisher}",
                    "needs_review": False
                }
        
        # Verificaciones adicionales
        if not publisher or publisher == "desconocido":
            return {
                "risk_level": "MEDIUM",
                "risk_category": "unknown_publisher",
                "risk_description": "Editor desconocido o no especificado",
                "risk_reason": "No se pudo determinar el editor del software",
                "needs_review": True
            }
        
        # Por defecto, clasificar como MEDIUM para revisión manual
        return {
            "risk_level": "MEDIUM",
            "risk_category": "unknown_software",
            "risk_description": "Software no clasificado",
            "risk_reason": "Software no encontrado en base de datos de confianza",
            "needs_review": True
        }

    def save_software_report(self, analyzed_software: List[Dict], output_dir: str = "reports") -> str:
        """Guarda el reporte de software en un archivo JSON."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"software_scan_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        # Filtrar solo software que requiere revisión
        software_to_review = [s for s in analyzed_software if s.get("needs_review", False)]
        
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_software": len(analyzed_software),
                "software_to_review": len(software_to_review),
                "scanner_version": "1.0"
            },
            "findings": software_to_review,
            "all_software": analyzed_software
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            if self.logger:
                self.logger.info(f"Reporte de software guardado: {filepath}")
                self.logger.info(f"Software total: {len(analyzed_software)}, Requiere revisión: {len(software_to_review)}")
            
            return filepath
            
        except Exception as e:
            error_msg = f"Error al guardar reporte de software: {e}"
            if self.logger:
                self.logger.error(error_msg)
            return ""

    def scan(self) -> str:
        """Método principal para ejecutar el escaneo completo de software."""
        if self.logger:
            self.logger.info("=== INICIANDO ESCANEO DE SOFTWARE ===")
        
        # Escanear software instalado
        installed_software = self.scan_installed_software()
        
        if not installed_software:
            if self.logger:
                self.logger.warning("No se encontró software instalado")
            return ""
        
        # Analizar riesgo
        analyzed_software = self.analyze_software_risk(installed_software)
        
        # Guardar reporte
        report_file = self.save_software_report(analyzed_software)
        
        # Mostrar resumen en logs
        self._log_software_summary(analyzed_software)
        
        return report_file

    def _log_software_summary(self, analyzed_software: List[Dict]) -> None:
        """Muestra un resumen del análisis de software en los logs."""
        if not self.logger:
            return
        
        # Contar por nivel de riesgo
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for software in analyzed_software:
            risk_level = software.get("risk_level", "MEDIUM")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        self.logger.info("=== RESUMEN DE ANÁLISIS DE SOFTWARE ===")
        self.logger.info(f"Software total analizado: {len(analyzed_software)}")
        self.logger.info(f"CRITICAL: {risk_counts['CRITICAL']}")
        self.logger.info(f"HIGH: {risk_counts['HIGH']}")
        self.logger.info(f"MEDIUM: {risk_counts['MEDIUM']}")
        self.logger.info(f"LOW: {risk_counts['LOW']}")
        
        # Mostrar software crítico y de alto riesgo
        critical_high = [s for s in analyzed_software if s.get("risk_level") in ["CRITICAL", "HIGH"]]
        if critical_high:
            self.logger.warning("⚠️  SOFTWARE DE ALTO RIESGO DETECTADO:")
            for software in critical_high:
                self.logger.warning(f"  - {software['name']} | {software['risk_level']} | {software['risk_reason']}")
