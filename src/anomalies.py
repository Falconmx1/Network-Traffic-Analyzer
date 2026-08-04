#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para detectar anomalías en el tráfico de red
Autor: Falconmx1
"""

import time
from collections import deque

class AnomalyDetector:
    """Detecta anomalías en el tráfico basándose en múltiples métricas"""
    
    def __init__(self, threshold=100, window_size=10):
        """
        Inicializa el detector de anomalías
        
        Args:
            threshold (int): Umbral de paquetes por segundo
            window_size (int): Tamaño de la ventana para historial
        """
        self.threshold = threshold
        self.window_size = window_size
        self.packet_timestamps = deque(maxlen=window_size)
        self.anomalies = []
        self.last_alert_time = 0
        self.alert_cooldown = 5  # segundos entre alertas
        
        # Para detección por protocolos sospechosos
        self.suspicious_protocols = {
            'SSH': {'min_rate': 1, 'max_rate': 10},
            'FTP': {'min_rate': 1, 'max_rate': 20},
            'DNS': {'min_rate': 1, 'max_rate': 50},
        }
        
        # Para detección de escaneo de puertos
        self.port_scan_threshold = 10  # puertos diferentes en 10 segundos
        self.ip_connections = {}  # IP -> {ports: set, last_seen: timestamp}
    
    def check_packet(self, packet_info, stats):
        """
        Verifica si un paquete es anómalo
        
        Args:
            packet_info (dict): Información del paquete
            stats (TrafficStats): Objeto de estadísticas
        
        Returns:
            tuple: (is_anomaly, details)
        """
        current_time = time.time()
        self.packet_timestamps.append(current_time)
        anomalies_found = []
        
        # 1. Detección por tasa de paquetes
        pps = self._calculate_pps()
        if pps > self.threshold:
            anomalies_found.append(
                f"Alta tasa de paquetes: {pps:.2f} pps (umbral: {self.threshold})"
            )
        
        # 2. Detección por protocolos sospechosos
        protocol = packet_info.get('protocol')
        if protocol in self.suspicious_protocols:
            protocol_anomaly = self._check_protocol_anomaly(protocol, stats)
            if protocol_anomaly:
                anomalies_found.append(protocol_anomaly)
        
        # 3. Detección de escaneo de puertos
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        if src_ip and dst_port:
            port_scan_anomaly = self._check_port_scan(src_ip, dst_port, current_time)
            if port_scan_anomaly:
                anomalies_found.append(port_scan_anomaly)
        
        # 4. Detección de tráfico inusual de ICMP
        if protocol == 'ICMP':
            if self._check_icmp_flood(stats):
                anomalies_found.append("Posible ICMP flood detectado")
        
        # Registrar anomalía si se encontró alguna
        if anomalies_found:
            details = ' | '.join(anomalies_found)
            # Evitar alertas duplicadas en corto tiempo
            if current_time - self.last_alert_time > self.alert_cooldown:
                self.anomalies.append(details)
                self.last_alert_time = current_time
                return True, details
        
        return False, None
    
    def _calculate_pps(self):
        """Calcula paquetes por segundo en la ventana actual"""
        if len(self.packet_timestamps) < 2:
            return 0
        
        timestamps = list(self.packet_timestamps)
        time_span = timestamps[-1] - timestamps[0]
        
        if time_span == 0:
            return 0
        
        return len(timestamps) / time_span
    
    def _check_protocol_anomaly(self, protocol, stats):
        """Verifica anomalías específicas de protocolos"""
        limits = self.suspicious_protocols.get(protocol)
        if not limits:
            return None
        
        # Obtener tasa actual del protocolo
        protocol_count = stats.protocols.get(protocol, 0)
        elapsed = time.time() - stats.start_time
        if elapsed == 0:
            return None
        
        rate = protocol_count / elapsed
        
        if rate > limits['max_rate']:
            return f"Alta tasa de {protocol}: {rate:.2f} pps (límite: {limits['max_rate']})"
        
        return None
    
    def _check_port_scan(self, src_ip, dst_port, current_time):
        """Detecta escaneo de puertos desde una IP"""
        if src_ip not in self.ip_connections:
            self.ip_connections[src_ip] = {'ports': set(), 'last_seen': current_time}
        
        ip_data = self.ip_connections[src_ip]
        ip_data['ports'].add(dst_port)
        ip_data['last_seen'] = current_time
        
        # Limpiar IPs antiguas (más de 30 segundos)
        for ip in list(self.ip_connections.keys()):
            if current_time - self.ip_connections[ip]['last_seen'] > 30:
                del self.ip_connections[ip]
        
        # Verificar si ha escaneado muchos puertos
        if len(ip_data['ports']) > self.port_scan_threshold:
            return f"Posible escaneo de puertos desde {src_ip}: {len(ip_data['ports'])} puertos"
        
        return None
    
    def _check_icmp_flood(self, stats):
        """Detecta posible ICMP flood"""
        icmp_count = stats.protocols.get('ICMP', 0)
        elapsed = time.time() - stats.start_time
        
        if elapsed == 0:
            return False
        
        icmp_rate = icmp_count / elapsed
        return icmp_rate > 50  # Más de 50 ICMP por segundo
    
    def get_anomalies(self):
        """Obtiene todas las anomalías detectadas"""
        return self.anomalies
    
    def reset(self):
        """Reinicia el detector"""
        self.anomalies = []
        self.packet_timestamps.clear()
        self.ip_connections.clear()
