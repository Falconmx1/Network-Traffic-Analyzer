#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la captura de paquetes de red usando Scapy
Autor: Falconmx1
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
import threading
import time

class Sniffer:
    """Clase para manejar la captura de paquetes"""
    
    def __init__(self, interface, packet_callback, filter=None):
        """
        Inicializa el sniffer
        
        Args:
            interface (str): Interfaz de red
            packet_callback (function): Función a llamar por cada paquete
            filter (str): Filtro BPF (ej: 'tcp port 80')
        """
        self.interface = interface
        self.packet_callback = packet_callback
        self.filter = filter or "ip"  # Capturar solo paquetes IP
        self.is_running = False
        self.sniff_thread = None
        
    def start(self):
        """Inicia la captura en un hilo separado"""
        if self.is_running:
            print("⚠️  El sniffer ya está en ejecución")
            return
        
        self.is_running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
    
    def _sniff_loop(self):
        """Bucle de captura de paquetes"""
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                filter=self.filter,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except PermissionError:
            print("❌ Permiso denegado. Ejecuta con sudo/administrador.")
            self.stop()
        except Exception as e:
            print(f"❌ Error en la captura: {e}")
            self.stop()
    
    def _handle_packet(self, packet):
        """Procesa un paquete capturado y extrae información"""
        packet_info = self._extract_packet_info(packet)
        if packet_info and self.packet_callback:
            self.packet_callback(packet_info)
    
    def _extract_packet_info(self, packet):
        """
        Extrae información relevante del paquete
        
        Returns:
            dict: Diccionario con los datos del paquete
        """
        info = {
            'timestamp': time.time(),
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'raw_data': None,
            'http': None,
            'dns': None
        }
        
        # Capa IP
        if IP in packet:
            ip_layer = packet[IP]
            info['src_ip'] = ip_layer.src
            info['dst_ip'] = ip_layer.dst
            info['protocol'] = ip_layer.proto
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                info['src_port'] = tcp.sport
                info['dst_port'] = tcp.dport
                info['protocol'] = 'TCP'
                
                # HTTP (puerto 80)
                if tcp.dport == 80 or tcp.sport == 80:
                    if Raw in packet:
                        try:
                            raw = packet[Raw].load.decode('utf-8', errors='ignore')
                            if 'HTTP' in raw:
                                info['http'] = self._parse_http(raw)
                        except:
                            pass
                
                # HTTPS (puerto 443)
                elif tcp.dport == 443 or tcp.sport == 443:
                    info['protocol'] = 'HTTPS'
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                info['src_port'] = udp.sport
                info['dst_port'] = udp.dport
                info['protocol'] = 'UDP'
                
                # DNS (puerto 53)
                if udp.dport == 53 or udp.sport == 53:
                    if DNS in packet:
                        info['protocol'] = 'DNS'
                        info['dns'] = self._parse_dns(packet[DNS])
            
            # ICMP
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
        
        # SSH (puerto 22)
        if info.get('src_port') == 22 or info.get('dst_port') == 22:
            info['protocol'] = 'SSH'
        
        # FTP (puerto 21)
        if info.get('src_port') == 21 or info.get('dst_port') == 21:
            info['protocol'] = 'FTP'
        
        return info
    
    def _parse_http(self, raw_data):
        """Analiza datos HTTP"""
        lines = raw_data.split('\r\n')
        if not lines:
            return None
        
        http_info = {'method': None, 'path': None, 'version': None}
        
        # Primera línea: GET /path HTTP/1.1
        first_line = lines[0].split(' ')
        if len(first_line) >= 3:
            http_info['method'] = first_line[0]
            http_info['path'] = first_line[1]
            http_info['version'] = first_line[2]
        
        # Headers
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        http_info['headers'] = headers
        return http_info
    
    def _parse_dns(self, dns_layer):
        """Analiza datos DNS"""
        dns_info = {}
        
        if dns_layer.qr == 0:  # Query
            dns_info['type'] = 'Query'
            if dns_layer.qd:
                dns_info['domain'] = dns_layer.qd.qname.decode('utf-8')
                dns_info['qtype'] = dns_layer.qd.qtype
        else:  # Response
            dns_info['type'] = 'Response'
            if dns_layer.an:
                dns_info['answers'] = []
                for ans in dns_layer.an:
                    dns_info['answers'].append({
                        'domain': ans.rrname.decode('utf-8'),
                        'type': ans.type,
                        'data': ans.rdata if hasattr(ans, 'rdata') else None
                    })
        
        return dns_info
    
    def stop(self):
        """Detiene la captura de paquetes"""
        self.is_running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
        print("✅ Sniffer detenido correctamente")
