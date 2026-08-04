#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pruebas unitarias para el módulo de detección de protocolos
Autor: Falconmx1
"""

import unittest
import sys
import os

# Añadir src al path para importar módulos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from protocols import ProtocolDetector, detect_protocol
from sniffer import Sniffer


class TestProtocolDetector(unittest.TestCase):
    """Pruebas para ProtocolDetector"""
    
    def setUp(self):
        """Configuración inicial para cada prueba"""
        self.detector = ProtocolDetector()
    
    def test_detect_by_port_known(self):
        """Prueba detección de protocolos por puertos conocidos"""
        test_cases = [
            (21, 'FTP'),
            (22, 'SSH'),
            (23, 'Telnet'),
            (25, 'SMTP'),
            (53, 'DNS'),
            (80, 'HTTP'),
            (110, 'POP3'),
            (143, 'IMAP'),
            (443, 'HTTPS'),
            (3306, 'MySQL'),
            (5432, 'PostgreSQL'),
            (6379, 'Redis'),
        ]
        
        for port, expected in test_cases:
            with self.subTest(port=port):
                result = self.detector.detect_by_port(port)
                self.assertEqual(result, expected, 
                                 f"Puerto {port} debería ser {expected}, pero devolvió {result}")
    
    def test_detect_by_port_unknown(self):
        """Prueba detección de puertos desconocidos"""
        unknown_ports = [12345, 54321, 9999, 31337]
        
        for port in unknown_ports:
            with self.subTest(port=port):
                result = self.detector.detect_by_port(port)
                self.assertIsNone(result, 
                                  f"Puerto {port} debería ser None, pero devolvió {result}")
    
    def test_detect_by_payload_http(self):
        """Prueba detección de HTTP por payload"""
        http_payloads = [
            b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            b"POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ]
        
        for payload in http_payloads:
            with self.subTest(payload=payload[:20]):
                result = self.detector.detect_by_payload(payload)
                self.assertEqual(result, 'HTTP', 
                                 f"Payload debería ser HTTP, pero devolvió {result}")
    
    def test_detect_by_payload_ssh(self):
        """Prueba detección de SSH por payload"""
        ssh_payloads = [
            b"SSH-2.0-OpenSSH_8.9p1\r\n",
            b"SSH-1.99-OpenSSH_7.4\r\n",
        ]
        
        for payload in ssh_payloads:
            with self.subTest(payload=payload[:10]):
                result = self.detector.detect_by_payload(payload)
                self.assertEqual(result, 'SSH',
                                 f"Payload debería ser SSH, pero devolvió {result}")
    
    def test_detect_by_payload_ftp(self):
        """Prueba detección de FTP por payload"""
        ftp_payloads = [
            b"220 ProFTPD 1.3.6 Server ready\r\n",
            b"USER usuario\r\n",
            b"PASS password\r\n",
            b"RETR archivo.txt\r\n",
            b"STOR datos.bin\r\n",
        ]
        
        for payload in ftp_payloads:
            with self.subTest(payload=payload[:10]):
                result = self.detector.detect_by_payload(payload)
                self.assertEqual(result, 'FTP',
                                 f"Payload debería ser FTP, pero devolvió {result}")
    
    def test_detect_by_payload_smtp(self):
        """Prueba detección de SMTP por payload"""
        smtp_payloads = [
            b"EHLO mail.example.com\r\n",
            b"MAIL FROM:<user@example.com>\r\n",
            b"RCPT TO:<dest@example.com>\r\n",
        ]
        
        for payload in smtp_payloads:
            with self.subTest(payload=payload[:10]):
                result = self.detector.detect_by_payload(payload)
                self.assertEqual(result, 'SMTP',
                                 f"Payload debería ser SMTP, pero devolvió {result}")
    
    def test_detect_with_packet_info(self):
        """Prueba detección completa con información de paquete"""
        test_cases = [
            # (packet_info, expected_protocol)
            (
                {'dst_port': 80, 'protocol': 'TCP'},
                'HTTP'  # HTTP debe detectarse por puerto aunque el protocolo base sea TCP
            ),
            (
                {'dst_port': 443, 'protocol': 'TCP'},
                'HTTPS'
            ),
            (
                {'dst_port': 22, 'protocol': 'TCP'},
                'SSH'
            ),
            (
                {'dst_port': 21, 'protocol': 'TCP'},
                'FTP'
            ),
            (
                {'dst_port': 53, 'protocol': 'UDP'},
                'DNS'
            ),
            (
                {'dst_port': 80, 'protocol': 'HTTP'},  # Ya detectado como HTTP
                'HTTP'
            ),
            (
                {'dst_port': 9999, 'protocol': 'TCP', 'src_ip': '192.168.1.1'},
                'TCP'  # Protocolo base cuando no se detecta específico
            ),
            (
                {'src_port': 22, 'protocol': 'TCP'},
                'SSH'  # SSH también se detecta por puerto origen
            ),
        ]
        
        for packet_info, expected in test_cases:
            with self.subTest(packet_info=packet_info):
                result = self.detector.detect(packet_info)
                self.assertEqual(result, expected,
                                 f"Para {packet_info} debería ser {expected}, pero devolvió {result}")
    
    def test_detect_protocol_helper(self):
        """Prueba la función helper detect_protocol"""
        packet_info = {'dst_port': 80, 'protocol': 'TCP'}
        result = detect_protocol(packet_info)
        self.assertEqual(result, 'HTTP')
        
        # Debe llamar al mismo método
        self.assertEqual(result, ProtocolDetector.detect(packet_info))
    
    def test_port_map_coverage(self):
        """Prueba que todos los puertos mapeados tengan un protocolo definido"""
        known_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 27017]
        for port in known_ports:
            self.assertIsNotNone(self.detector.detect_by_port(port),
                                 f"Puerto {port} debería estar mapeado")
    
    def test_patterns_coverage(self):
        """Prueba que los patrones para payload contengan valores válidos"""
        for protocol, patterns in self.detector.PATTERNS.items():
            self.assertIsInstance(patterns, list,
                                 f"Los patrones de {protocol} deben ser lista")
            self.assertGreater(len(patterns), 0,
                              f"Debe haber al menos un patrón para {protocol}")
            for pattern in patterns:
                self.assertIsInstance(pattern, bytes,
                                     f"Los patrones deben ser bytes: {pattern}")


class TestSnifferExtraction(unittest.TestCase):
    """Pruebas para la extracción de información de paquetes"""
    
    def setUp(self):
        """Configuración de prueba"""
        self.sniffer = Sniffer(interface='dummy', packet_callback=lambda x: None)
    
    def test_extract_packet_info_tcp(self):
        """Prueba extracción de información de paquetes TCP"""
        # Creamos un paquete simulado con scapy
        from scapy.all import IP, TCP
        
        test_cases = [
            (IP(src='192.168.1.100', dst='10.0.0.1')/TCP(sport=54321, dport=80), 
             {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.1', 
              'src_port': 54321, 'dst_port': 80, 'protocol': 'TCP'}),
            (IP(src='10.0.0.5', dst='192.168.1.200')/TCP(sport=22, dport=12345),
             {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.200',
              'src_port': 22, 'dst_port': 12345, 'protocol': 'TCP'}),
        ]
        
        for packet, expected in test_cases:
            with self.subTest(packet=packet.summary()):
                result = self.sniffer._extract_packet_info(packet)
                # Verificar campos clave
                for key, value in expected.items():
                    self.assertEqual(result.get(key), value,
                                   f"Campo {key} debería ser {value}, pero es {result.get(key)}")
    
    def test_extract_packet_info_udp(self):
        """Prueba extracción de información de paquetes UDP"""
        from scapy.all import IP, UDP
        
        test_cases = [
            (IP(src='192.168.1.100', dst='8.8.8.8')/UDP(sport=12345, dport=53),
             {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
              'src_port': 12345, 'dst_port': 53, 'protocol': 'UDP'}),
        ]
        
        for packet, expected in test_cases:
            with self.subTest(packet=packet.summary()):
                result = self.sniffer._extract_packet_info(packet)
                for key, value in expected.items():
                    self.assertEqual(result.get(key), value,
                                   f"Campo {key} debería ser {value}, pero es {result.get(key)}")
    
    def test_extract_packet_info_icmp(self):
        """Prueba extracción de información de paquetes ICMP"""
        from scapy.all import IP, ICMP
        
        packet = IP(src='192.168.1.100', dst='8.8.8.8')/ICMP(type=8, code=0)
        result = self.sniffer._extract_packet_info(packet)
        
        self.assertEqual(result.get('src_ip'), '192.168.1.100')
        self.assertEqual(result.get('dst_ip'), '8.8.8.8')
        self.assertEqual(result.get('protocol'), 'ICMP')
    
    def test_parse_http(self):
        """Prueba parsing de datos HTTP"""
        raw_http = """GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html

"""
        result = self.sniffer._parse_http(raw_http)
        
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['version'], 'HTTP/1.1')
        self.assertEqual(result['headers']['Host'], 'example.com')
        self.assertEqual(result['headers']['User-Agent'], 'Mozilla/5.0')
    
    def test_parse_dns_query(self):
        """Prueba parsing de consultas DNS"""
        from scapy.all import IP, UDP, DNS, DNSQR
        
        packet = IP(src='192.168.1.100', dst='8.8.8.8')/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname='google.com'))
        
        # Crear una instancia de Sniffer con un callback dummy
        sniffer = Sniffer(interface='dummy', packet_callback=lambda x: None)
        
        # Extraer información del paquete
        info = sniffer._extract_packet_info(packet)
        
        # Verificar que el DNS fue detectado
        self.assertEqual(info['protocol'], 'DNS')
        self.assertIsNotNone(info['dns'])
        self.assertEqual(info['dns']['type'], 'Query')
        self.assertEqual(info['dns']['domain'], 'google.com')


class TestAnomaliesIntegration(unittest.TestCase):
    """Pruebas de integración para detección de anomalías"""
    
    def test_anomaly_detection_import(self):
        """Prueba que el módulo de anomalías se pueda importar"""
        try:
            from anomalies import AnomalyDetector
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"No se pudo importar AnomalyDetector: {e}")
    
    def test_stats_import(self):
        """Prueba que el módulo de estadísticas se pueda importar"""
        try:
            from stats import TrafficStats
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"No se pudo importar TrafficStats: {e}")
    
    def test_exporter_import(self):
        """Prueba que el módulo de exportación se pueda importar"""
        try:
            from exporter import ReportExporter
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"No se pudo importar ReportExporter: {e}")


if __name__ == '__main__':
    # Ejecutar pruebas
    unittest.main(verbosity=2)
