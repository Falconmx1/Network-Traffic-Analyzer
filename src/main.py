#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Traffic Analyzer - Punto de entrada principal
Autor: Falconmx1
"""

import argparse
import sys
import signal
from colorama import init, Fore, Style

# Inicializar colorama para colores en consola
init(autoreset=True)

from sniffer import Sniffer
from stats import TrafficStats
from anomalies import AnomalyDetector
from exporter import ReportExporter

class NetworkTrafficAnalyzer:
    """Clase principal que orquesta el análisis de tráfico"""
    
    def __init__(self, interface, output=None, anomaly_threshold=100):
        self.interface = interface
        self.output = output
        self.anomaly_threshold = anomaly_threshold
        self.running = False
        
        # Inicializar componentes
        self.stats = TrafficStats()
        self.anomaly_detector = AnomalyDetector(threshold=anomaly_threshold)
        self.exporter = ReportExporter()
        self.sniffer = None
        
        print(Fore.CYAN + "="*60)
        print(Fore.GREEN + "🌐 Network Traffic Analyzer v1.0.0")
        print(Fore.CYAN + "="*60)
        print(f"📡 Interfaz: {Fore.YELLOW}{interface}")
        print(f"📊 Umbral de anomalías: {Fore.YELLOW}{anomaly_threshold} pps")
        if output:
            print(f"📄 Reporte: {Fore.YELLOW}{output}")
        print(Fore.CYAN + "="*60 + "\n")
    
    def start(self):
        """Inicia la captura de tráfico"""
        try:
            self.running = True
            self.sniffer = Sniffer(
                interface=self.interface,
                packet_callback=self._process_packet
            )
            
            # Configurar manejador de señales para Ctrl+C
            signal.signal(signal.SIGINT, self._signal_handler)
            
            print(Fore.GREEN + "✅ Captura iniciada. Presiona Ctrl+C para detener.\n")
            self.sniffer.start()
            
        except Exception as e:
            print(Fore.RED + f"❌ Error: {e}")
            self.stop()
    
    def _process_packet(self, packet):
        """Callback para procesar cada paquete capturado"""
        # Actualizar estadísticas
        protocol = self.stats.update(packet)
        
        # Verificar anomalías
        is_anomaly, details = self.anomaly_detector.check_packet(packet, self.stats)
        
        # Mostrar información en tiempo real (opcional)
        if protocol:
            print(f"{Fore.LIGHTBLACK_EX}[+] Paquete: {protocol} | "
                  f"Origen: {packet.get('src_ip', 'N/A')} -> "
                  f"Destino: {packet.get('dst_ip', 'N/A')}")
        
        if is_anomaly:
            print(Fore.RED + f"⚠️  ANOMALÍA DETECTADA: {details}")
    
    def _signal_handler(self, sig, frame):
        """Maneja Ctrl+C para detener la captura"""
        print(Fore.YELLOW + "\n\n⏹️  Deteniendo captura...")
        self.stop()
    
    def stop(self):
        """Detiene la captura y genera reporte si es necesario"""
        if self.sniffer:
            self.sniffer.stop()
        
        self.running = False
        
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.GREEN + "📊 RESUMEN DE ESTADÍSTICAS")
        print(Fore.CYAN + "="*60)
        
        # Mostrar estadísticas
        stats_summary = self.stats.get_summary()
        print(f"📦 Paquetes totales: {Fore.YELLOW}{stats_summary['total_packets']}")
        print(f"📋 Protocolos detectados: {Fore.YELLOW}{len(stats_summary['protocols'])}")
        print(f"🔢 IPs únicas: {Fore.YELLOW}{stats_summary['unique_ips']}")
        
        print(Fore.CYAN + "\n" + "🔍 Protocolos detectados:")
        for proto, count in stats_summary['protocols'].items():
            print(f"   - {Fore.YELLOW}{proto}: {count} paquetes")
        
        # Detectar anomalías en el resumen final
        anomalies = self.anomaly_detector.get_anomalies()
        if anomalies:
            print(Fore.RED + f"\n⚠️  ANOMALÍAS DETECTADAS: {len(anomalies)}")
            for anomaly in anomalies:
                print(Fore.RED + f"   - {anomaly}")
        else:
            print(Fore.GREEN + "\n✅ No se detectaron anomalías.")
        
        # Exportar reporte si se especificó
        if self.output:
            print(Fore.CYAN + f"\n📄 Generando reporte: {self.output}")
            self.exporter.export(
                stats=stats_summary,
                anomalies=anomalies,
                filename=self.output
            )
            print(Fore.GREEN + "✅ Reporte generado exitosamente.")
        
        print(Fore.CYAN + "="*60)
        print(Fore.GREEN + "👋 Análisis finalizado. ¡Hasta luego!")
        sys.exit(0)

def main():
    """Función principal con manejo de argumentos"""
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer - Análisis de tráfico en tiempo real",
        epilog="Ejemplo: python main.py -i eth0 -o reporte.pdf"
    )
    
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Interfaz de red a monitorear (ej: eth0, wlan0)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Archivo de salida para el reporte (ej: reporte.pdf, stats.csv)'
    )
    
    parser.add_argument(
        '--anomaly-threshold',
        type=int,
        default=100,
        help='Umbral de paquetes por segundo para detectar anomalías (default: 100)'
    )
    
    args = parser.parse_args()
    
    # Crear y ejecutar el analizador
    analyzer = NetworkTrafficAnalyzer(
        interface=args.interface,
        output=args.output,
        anomaly_threshold=args.anomaly_threshold
    )
    
    analyzer.start()

if __name__ == "__main__":
    main()
