#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para calcular estadísticas de tráfico en tiempo real
Autor: Falconmx1
"""

import time
from collections import defaultdict, Counter
from datetime import datetime

class TrafficStats:
    """Recopila y calcula estadísticas de tráfico"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reinicia todas las estadísticas"""
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        
        # Contadores por protocolo
        self.protocols = Counter()
        
        # Tráfico por IP
        self.src_ips = Counter()
        self.dst_ips = Counter()
        
        # Tráfico por puerto
        self.src_ports = Counter()
        self.dst_ports = Counter()
        
        # Histórico para análisis de tendencias (ventana de 60 segundos)
        self.packet_history = defaultdict(list)  # timestamp -> lista de bytes
        self.history_window = 60  # segundos
        
        # Tasa de paquetes por segundo
        self.pps_history = []
    
    def update(self, packet_info):
        """
        Actualiza estadísticas con un nuevo paquete
        
        Args:
            packet_info (dict): Información del paquete
        
        Returns:
            str: Protocolo detectado
        """
        self.total_packets += 1
        self.total_bytes += packet_info.get('length', 0)
        
        # Protocolo
        protocol = packet_info.get('protocol', 'Unknown')
        self.protocols[protocol] += 1
        
        # IPs
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if src_ip:
            self.src_ips[src_ip] += 1
        if dst_ip:
            self.dst_ips[dst_ip] += 1
        
        # Puertos
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        if src_port:
            self.src_ports[src_port] += 1
        if dst_port:
            self.dst_ports[dst_port] += 1
        
        # Histórico para tasa de paquetes
        current_time = time.time()
        self.packet_history[current_time].append(packet_info.get('length', 0))
        
        # Limpiar datos antiguos
        self._clean_history(current_time)
        
        # Actualizar tasa de paquetes (cada 5 segundos)
        if current_time - self.last_update >= 5:
            self._update_pps(current_time)
            self.last_update = current_time
        
        return protocol
    
    def _clean_history(self, current_time):
        """Elimina datos históricos antiguos"""
        cutoff = current_time - self.history_window
        for ts in list(self.packet_history.keys()):
            if ts < cutoff:
                del self.packet_history[ts]
    
    def _update_pps(self, current_time):
        """Calcula y almacena la tasa de paquetes por segundo"""
        cutoff = current_time - 5  # Últimos 5 segundos
        packets_count = sum(
            len(packets) for ts, packets in self.packet_history.items()
            if ts >= cutoff
        )
        self.pps_history.append(packets_count / 5)
        
        # Mantener solo los últimos 60 valores (5 minutos aprox)
        if len(self.pps_history) > 60:
            self.pps_history.pop(0)
    
    def get_summary(self):
        """
        Obtiene un resumen de las estadísticas
        
        Returns:
            dict: Resumen estadístico
        """
        elapsed = time.time() - self.start_time
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'elapsed_time': elapsed,
            'packets_per_second': self.total_packets / elapsed if elapsed > 0 else 0,
            'bytes_per_second': self.total_bytes / elapsed if elapsed > 0 else 0,
            'protocols': dict(self.protocols),
            'top_src_ips': self.src_ips.most_common(10),
            'top_dst_ips': self.dst_ips.most_common(10),
            'top_src_ports': self.src_ports.most_common(10),
            'top_dst_ports': self.dst_ports.most_common(10),
            'unique_ips': len(set(self.src_ips.keys()) | set(self.dst_ips.keys())),
            'pps_history': self.pps_history[-20:]  # Últimos 20 valores
        }
    
    def get_protocol_distribution(self):
        """Obtiene distribución de protocolos en porcentaje"""
        if self.total_packets == 0:
            return {}
        
        distribution = {}
        for protocol, count in self.protocols.items():
            distribution[protocol] = (count / self.total_packets) * 100
        
        return distribution
    
    def get_current_pps(self):
        """Obtiene la tasa de paquetes por segundo en este momento"""
        if not self.pps_history:
            return 0
        return self.pps_history[-1]
