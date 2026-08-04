#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para detectar y clasificar protocolos de red
Autor: Falconmx1
"""

class ProtocolDetector:
    """Detecta protocolos basados en puertos y patrones"""
    
    # Mapeo de puertos a protocolos
    PORT_MAP = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    
    # Patrones para detección basada en payload
    PATTERNS = {
        'HTTP': [b'HTTP/', b'GET ', b'POST ', b'PUT ', b'DELETE '],
        'FTP': [b'220 ', b'USER ', b'PASS ', b'RETR ', b'STOR '],
        'SSH': [b'SSH-'],
        'SMTP': [b'EHLO ', b'MAIL FROM:', b'RCPT TO:'],
        'DNS': [b'\x00\x01\x00\x00\x00\x00\x00\x00'],  # Cabecera DNS simplificada
    }
    
    @classmethod
    def detect_by_port(cls, port):
        """
        Detecta protocolo por puerto
        
        Args:
            port (int): Número de puerto
        
        Returns:
            str: Nombre del protocolo o None
        """
        return cls.PORT_MAP.get(port)
    
    @classmethod
    def detect_by_payload(cls, payload):
        """
        Detecta protocolo por payload
        
        Args:
            payload (bytes): Datos del paquete
        
        Returns:
            str: Nombre del protocolo o None
        """
        if not payload:
            return None
        
        for protocol, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if pattern in payload:
                    return protocol
        
        return None
    
    @classmethod
    def detect(cls, packet_info):
        """
        Detecta el protocolo usando puerto y payload
        
        Args:
            packet_info (dict): Información del paquete
        
        Returns:
            str: Protocolo detectado
        """
        protocol = None
        
        # 1. Por puerto
        dst_port = packet_info.get('dst_port')
        src_port = packet_info.get('src_port')
        
        if dst_port:
            protocol = cls.detect_by_port(dst_port)
        if not protocol and src_port:
            protocol = cls.detect_by_port(src_port)
        
        # 2. Si ya se detectó en sniffer, mantenerlo
        if packet_info.get('protocol') in ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS']:
            return packet_info['protocol']
        
        # 3. Por payload (si está disponible)
        if not protocol and packet_info.get('raw_data'):
            protocol = cls.detect_by_payload(packet_info['raw_data'])
        
        # 4. Clasificación genérica
        if not protocol:
            ip_proto = packet_info.get('protocol')
            if ip_proto == 6:
                protocol = 'TCP'
            elif ip_proto == 17:
                protocol = 'UDP'
            elif ip_proto == 1:
                protocol = 'ICMP'
            else:
                protocol = f'IP-{ip_proto}'
        
        return protocol

# Función helper para uso rápido
def detect_protocol(packet_info):
    """Helper para detectar protocolo"""
    return ProtocolDetector.detect(packet_info)
