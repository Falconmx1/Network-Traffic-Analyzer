
# Network Traffic Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**Network Traffic Analyzer** es una herramienta en tiempo real para monitoreo de red. Detecta protocolos (HTTP, HTTPS, SSH, FTP, DNS), muestra estadísticas, detecta anomalías y exporta reportes en PDF/CSV. Ideal para pentesting y administración de redes.

## 🚀 Características

- ✅ Captura de tráfico en tiempo real
- ✅ Detección de protocolos: HTTP, HTTPS, SSH, FTP, DNS
- ✅ Estadísticas por IP y puerto
- ✅ Detección de anomalías (umbrales configurables)
- ✅ Exportación de reportes a PDF y CSV
- ✅ Interfaz por línea de comandos (CLI)

## 📦 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/Network-Traffic-Analyzer.git
cd Network-Traffic-Analyzer

# Instalar dependencias
pip install -r requirements.txt

🔧 Uso Básico
# Mostrar ayuda
python src/main.py -h

# Capturar tráfico en la interfaz eth0
python src/main.py -i eth0

# Capturar y exportar a PDF
python src/main.py -i eth0 -o reporte.pdf

# Detectar anomalías con umbral personalizado
python src/main.py -i eth0 --anomaly-threshold 100

Argumentos disponibles
Argumento                 Descripción
-i, --interface           Interfaz de red a monitorear
-o, --output              Archivo de salida para el reporte (PDF/CSV)
--anomaly-threshold       Umbral de paquetes por segundo para detectar anomalías

🤝 Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request para sugerir cambios o mejoras.

👤 Autor
Falconmx1

GitHub: @Falconmx1

