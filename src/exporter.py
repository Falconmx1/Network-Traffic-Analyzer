#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para exportar estadísticas a PDF, CSV y otros formatos
Autor: Falconmx1
"""

import csv
import json
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Title
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
import matplotlib.pyplot as plt
import io

class ReportExporter:
    """Exporta reportes en diferentes formatos"""
    
    def __init__(self):
        self.supported_formats = ['pdf', 'csv', 'json', 'html']
    
    def export(self, stats, anomalies, filename):
        """
        Exporta un reporte con estadísticas y anomalías
        
        Args:
            stats (dict): Estadísticas resumidas
            anomalies (list): Lista de anomalías detectadas
            filename (str): Nombre del archivo de salida
        
        Returns:
            bool: True si fue exitoso
        """
        try:
            # Detectar formato por extensión
            _, ext = os.path.splitext(filename)
            ext = ext.lower().replace('.', '')
            
            if ext not in self.supported_formats:
                print(f"⚠️  Formato no soportado: {ext}. Usando CSV por defecto.")
                ext = 'csv'
            
            # Llamar al método correspondiente
            method_name = f'_export_{ext}'
            if hasattr(self, method_name):
                getattr(self, method_name)(stats, anomalies, filename)
                return True
            else:
                print(f"❌ Método de exportación no implementado: {ext}")
                return False
        
        except Exception as e:
            print(f"❌ Error al exportar reporte: {e}")
            return False
    
    def _export_pdf(self, stats, anomalies, filename):
        """Exporta a PDF usando ReportLab"""
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        
        # Título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30
        )
        elements.append(Paragraph("Network Traffic Analyzer - Reporte", title_style))
        elements.append(Paragraph(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Estadísticas generales
        elements.append(Paragraph("Estadísticas Generales", styles['Heading2']))
        stats_data = [
            ['Métrica', 'Valor'],
            ['Paquetes totales', str(stats['total_packets'])],
            ['Bytes totales', f"{stats['total_bytes']:,}"],
            ['Tiempo de captura', f"{stats['elapsed_time']:.2f} segundos"],
            ['Paquetes por segundo', f"{stats['packets_per_second']:.2f}"],
            ['IPs únicas', str(stats['unique_ips'])],
        ]
        stats_table = Table(stats_data)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 20))
        
        # Protocolos
        elements.append(Paragraph("Distribución de Protocolos", styles['Heading2']))
        proto_data = [['Protocolo', 'Paquetes', 'Porcentaje']]
        total = stats['total_packets']
        for proto, count in stats['protocols'].items():
            percentage = (count / total * 100) if total > 0 else 0
            proto_data.append([proto, str(count), f"{percentage:.1f}%"])
        
        proto_table = Table(proto_data)
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(proto_table)
        elements.append(Spacer(1, 20))
        
        # Top IPs
        elements.append(Paragraph("Top 5 IPs de Origen", styles['Heading2']))
        src_data = [['IP', 'Paquetes']] + stats['top_src_ips'][:5]
        src_table = Table(src_data)
        src_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(src_table)
        
        # Anomalías
        if anomalies:
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("Anomalías Detectadas", styles['Heading2']))
            for anomaly in anomalies:
                elements.append(Paragraph(f"⚠️  {anomaly}", styles['Normal']))
        else
