# Guía de Uso - Network Traffic Analyzer

Guía completa para instalar, configurar y utilizar el Network Traffic Analyzer.

---

## 📋 Índice

1. [Requisitos Previos](#requisitos-previos)
2. [Instalación](#instalación)
3. [Configuración](#configuración)
4. [Uso Básico](#uso-básico)
5. [Opciones Avanzadas](#opciones-avanzadas)
6. [Detección de Anomalías](#detección-de-anomalías)
7. [Exportación de Reportes](#exportación-de-reportes)
8. [Ejemplos Prácticos](#ejemplos-prácticos)
9. [Solución de Problemas](#solución-de-problemas)
10. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## Requisitos Previos

### Sistema Operativo
- **Linux** (recomendado: Ubuntu 20.04+, Debian 11+)
- **macOS** (10.15+)
- **Windows** (con WSL2 o Npcap instalado)

### Permisos
- **Root/Administrador**: Necesario para capturar tráfico en modo promiscuo.
- En Linux/macOS: `sudo`
- En Windows: Ejecutar como administrador

### Dependencias del Sistema
```bash
# En Linux (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y python3 python3-pip tcpdump

# En macOS (con Homebrew)
brew install python3 tcpdump

# En Windows (con WSL2)
# Instalar Npcap desde: https://npcap.com/

Instalación
1. Clonar el repositorio
git clone https://github.com/Falconmx1/Network-Traffic-Analyzer.git
cd Network-Traffic-Analyzer

2. Instalar dependencias de Python
pip install -r requirements.txt

3. Verificar instalación
python src/main.py -h
Deberías ver el mensaje de ayuda con todas las opciones disponibles.

Configuración
Configuración por defecto
La herramienta funciona con valores predeterminados, pero puedes personalizarla:

Umbral de anomalías
Modifica el archivo src/anomalies.py para cambiar los umbrales:
# Líneas 13-17
self.threshold = 100  # Paquetes por segundo para alerta
self.suspicious_protocols = {
    'SSH': {'min_rate': 1, 'max_rate': 10},
    'FTP': {'min_rate': 1, 'max_rate': 20},
    'DNS': {'min_rate': 1, 'max_rate': 50},
}
Formato de reportes
Los reportes se generan en estos formatos (según extensión):

.pdf - PDF con gráficos y tablas

.csv - Datos en formato CSV

.json - Datos estructurados en JSON

.html - Reporte HTML visual

Uso Básico
Comando principal
sudo python src/main.py -i [INTERFAZ] [OPCIONES]

Ejemplo mínimo
# Capturar tráfico en la interfaz eth0
sudo python src/main.py -i eth0

Mostrar ayuda
python src/main.py -h

Salida del programa
Durante la ejecución verás:

📡 Información de la interfaz y configuración

🔄 Paquetes en tiempo real con protocolos detectados

⚠️ Alertas de anomalías en rojo

📊 Resumen final al detener (Ctrl+C)

Opciones Avanzadas
Lista completa de argumentos
Argumento                 Descripción                           Ejemplo
-i, --interface           Requerido. Interfaz de red            -i eth0
-o, --output              Archivo de salida para reporte        -o reporte.pdf
--anomaly-threshold       Umbral de paquetes por segundo        --anomaly-threshold 200

Combinación de opciones
# Capturar en wlan0 con umbral personalizado y exportar a PDF
sudo python src/main.py -i wlan0 --anomaly-threshold 150 -o analisis.pdf

# Exportar a CSV con umbral bajo
sudo python src/main.py -i eth0 --anomaly-threshold 50 -o estadisticas.csv

Detección de Anomalías
La herramienta detecta automáticamente estos tipos de anomalías:

1. Alta tasa de paquetes
Descripción: Cuando el tráfico supera el umbral configurado.

Umbral por defecto: 100 paquetes/segundo.

Ejemplo: ⚠️ Alta tasa de paquetes: 245.30 pps (umbral: 100)

2. Protocolos sospechosos
SSH: Más de 10 paquetes/segundo

FTP: Más de 20 paquetes/segundo

DNS: Más de 50 paquetes/segundo

Ejemplo: ⚠️ Alta tasa de SSH: 15.20 pps (límite: 10)

3. Escaneo de puertos
Descripción: Una IP contacta más de 10 puertos diferentes en 10 segundos.

Ejemplo: ⚠️ Posible escaneo de puertos desde 192.168.1.100: 15 puertos

4. ICMP Flood
Descripción: Más de 50 paquetes ICMP por segundo.

Ejemplo: ⚠️ Posible ICMP flood detectado

Exportación de Reportes
Formatos soportados
📄 PDF
sudo python src/main.py -i eth0 -o reporte.pdf

Ideal para presentaciones y documentación

Incluye tablas y gráficos

Formato profesional

📊 CSV
sudo python src/main.py -i eth0 -o datos.csv
Abre con Excel, Google Sheets o cualquier editor de texto

Datos estructurados para análisis posterior

Útil para procesamiento con otras herramientas

📋 JSON
sudo python src/main.py -i eth0 -o datos.json

Formato estructurado para APIs

Fácil de parsear con cualquier lenguaje

Ideal para integración con otras herramientas

🌐 HTML
sudo python src/main.py -i eth0 -o reporte.html
Visualización en navegador

Interfaz amigable

Listo para compartir

Contenido del reporte
Todos los reportes incluyen:

1. Fecha y hora del análisis

2. Estadísticas generales (paquetes, bytes, tiempo)

3. Distribución de protocolos (HTTP, HTTPS, SSH, etc.)

4. Top IPs de origen y destino

5. Lista de anomalías detectadas

Ejemplos Prácticos
1. Análisis rápido de red
# Capturar 30 segundos en la interfaz principal
sudo python src/main.py -i eth0 -o analisis_rapido.pdf
# Esperar 30 segundos y presionar Ctrl+C

2. Monitoreo de servidor web

# Enfocado en tráfico HTTP/HTTPS con umbral alto
sudo python src/main.py -i eth0 --anomaly-threshold 500 -o web_report.pdf
3. Detección de ataques DoS

# Umbral bajo para detectar inundaciones
sudo python src/main.py -i eth0 --anomaly-threshold 50 -o dos_detection.csv
4. Auditoría de seguridad

# Captura prolongada con reporte completo
sudo python src/main.py -i wlan0 -o security_audit.html
# Dejar corriendo 1 hora para análisis completo
Solución de Problemas
Error: Permission denied

# Solución: Ejecutar con sudo (Linux/macOS)
sudo python src/main.py -i eth0

# En Windows: Ejecutar como administrador en PowerShell/CMD
Error: No module named 'scapy'

# Instalar dependencias manualmente
pip install scapy reportlab matplotlib pyyaml tabulate prettytable colorama
Error: Interface eth0 not found

# Listar interfaces disponibles
ip link show        # Linux
ifconfig            # macOS/Linux
ipconfig            # Windows

# Usar una interfaz válida, ej: wlan0, en0, Wi-Fi
Error: ImportError: No module named 'src'

# Asegurarse de estar en la raíz del proyecto
cd /ruta/al/Network-Traffic-Analyzer
python src/main.py -i eth0
El sniffer no captura paquetes en Wi-Fi

# En algunos sistemas, la interfaz Wi-Fi necesita modo monitor
# Linux:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# O usar interfaces con cable (eth0) para pruebas iniciales

Preguntas Frecuentes
¿Puedo ejecutarlo en Windows?
Sí, con WSL2 (Windows Subsystem for Linux) o instalando Npcap y usando Python directamente en CMD/PowerShell (con permisos de administrador).

¿Qué hago si veo muchas anomalías?
Ajusta el umbral con --anomaly-threshold según tu entorno. Una red empresarial puede tener 200+ pps normalmente.

¿Cómo detengo la captura?
Presiona Ctrl+C en cualquier momento. La herramienta mostrará el resumen automáticamente.

¿Puedo analizar archivos .pcap?
Esta versión es para análisis en tiempo real. La funcionalidad offline estará disponible en futuras versiones.

¿Qué información NO se captura?
Contenido de paquetes cifrados (HTTPS, SSH)

Datos de aplicaciones (solo metadatos)

Tráfico no IP (ARP, etc.)

🔗 Enlaces útiles
Repositorio en GitHub - https://github.com/Falconmx1/Network-Traffic-Analyzer

Documentación de Scapy - https://scapy.readthedocs.io/en/latest/

ReportLab PDF Guide - https://www.reportlab.com/docs/reportlab-userguide.pdf

Reportar Issues - https://github.com/Falconmx1/Network-Traffic-Analyzer/issues

Issues

📝 Contribuciones
¿Encontraste un bug o tienes una sugerencia? Abre un issue o pull request en el repositorio. ¡Toda ayuda es bienvenida!

