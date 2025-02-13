# SECInspector
Herramienta de Seguridad y Auditoría 

Escaneo de Puertos y Servicios

    Similar a Nmap, detectar qué puertos están abiertos en un servidor o red local.
    Identificar servicios corriendo en cada puerto y sus versiones.

Detección de Vulnerabilidades Básica

    Comparar versiones de servicios con bases de datos de vulnerabilidades conocidas (por ejemplo, CVE).
    Sugerir actualizaciones o mitigaciones.

Análisis de Configuración de Seguridad

    Revisar permisos en archivos y carpetas sensibles.
    Identificar configuraciones inseguras en servidores web (Apache, Nginx, etc.).

Monitoreo de Tráfico y Detección de Actividad Sospechosa

    Capturar paquetes de red y analizar si hay actividad inusual (sniffing con Scapy o Tshark).
    Detectar intentos de fuerza bruta o conexiones sospechosas.

Escaneo de Redes WiFi

    Identificar redes disponibles y su seguridad (WPA2, WEP, etc.).
    Buscar dispositivos conectados en una red.

Interfaz Web o CLI Interactiva

    Puedes hacer una interfaz en Flask/FastAPI o una CLI bien estructurada con argparse y rich para visualización.
