import os
import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

class SecurityReporter:
    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize monitoring data
        self.monitoring_data = []
        self.alert_thresholds = {
            'total_vulnerability_score': 0.7,
            'data_security_risks': 0.7,
            'authentication_risks': 0.7,
            'api_security_risks': 0.7,
            'runtime_security_risks': 0.7
        }
    
    def generate_pdf_report(self, results: Dict[str, Any], app_name: str = 'Mobile App') -> str:
        """Generate a detailed PDF security report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f'security_report_{timestamp}.pdf')
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph(f'{app_name} Security Assessment Report', title_style))
        story.append(Spacer(1, 20))
        
        # Overall Score
        score_style = ParagraphStyle(
            'ScoreStyle',
            parent=styles['Normal'],
            fontSize=16,
            textColor=self._get_score_color(results['total_vulnerability_score'])
        )
        story.append(Paragraph(
            f'Total Vulnerability Score: {results["total_vulnerability_score"]:.2%}',
            score_style
        ))
        story.append(Spacer(1, 20))
        
        # Vulnerability Breakdown
        story.append(Paragraph('Vulnerability Breakdown', styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Create vulnerability breakdown table
        table_data = [
            ['Risk Category', 'Score', 'Risk Level']
        ]
        for vuln_type, details in results['vulnerability_breakdown'].items():
            table_data.append([
                vuln_type.replace('_', ' ').title(),
                f'{details["score"]:.2%}',
                details['risk_level']
            ])
        
        table = Table(table_data, colWidths=[250, 100, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Add risk factors analysis
        story.append(Paragraph('Risk Factors Analysis', styles['Heading2']))
        story.append(Spacer(1, 10))
        
        risk_table_data = [
            ['Factor', 'Weight', 'Impact']
        ]
        for factor, details in results['risk_factors'].items():
            risk_table_data.append([
                factor.replace('_', ' ').title(),
                f'{details["weight"]:.2%}',
                f'{details["impact"]:.2%}'
            ])
        
        risk_table = Table(risk_table_data, colWidths=[250, 100, 100])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        
        # Build the PDF
        doc.build(story)
        self.logger.info(f'PDF report generated: {output_file}')
        return output_file
    
    def _get_score_color(self, score: float) -> colors.Color:
        """Return color based on vulnerability score"""
        if score > 0.7:
            return colors.red
        elif score > 0.4:
            return colors.orange
        return colors.green
    
    def update_monitoring_data(self, results: Dict[str, Any]):
        """Update real-time monitoring data and check for alerts"""
        timestamp = datetime.now().isoformat()
        monitoring_entry = {
            'timestamp': timestamp,
            'total_vulnerability_score': results['total_vulnerability_score'],
            'vulnerability_breakdown': results['vulnerability_breakdown']
        }
        self.monitoring_data.append(monitoring_entry)
        
        # Check for alerts
        self._check_alerts(results)
        
        # Save monitoring data
        self._save_monitoring_data()
    
    def _check_alerts(self, results: Dict[str, Any]):
        """Check for security alerts based on thresholds"""
        alerts = []
        
        # Check overall vulnerability score
        if results['total_vulnerability_score'] >= self.alert_thresholds['total_vulnerability_score']:
            alerts.append(f'High overall vulnerability score: {results["total_vulnerability_score"]:.2%}')
        
        # Check individual risk categories
        for vuln_type, details in results['vulnerability_breakdown'].items():
            if details['score'] >= self.alert_thresholds.get(vuln_type, 0.7):
                alerts.append(f'High {vuln_type} score: {details["score"]:.2%}')
        
        if alerts:
            self._send_alerts(alerts)
    
    def _send_alerts(self, alerts: List[str]):
        """Send security alerts (implement your preferred notification method)"""
        alert_message = '\n'.join(['SECURITY ALERT:', *alerts])
        self.logger.warning(alert_message)
        # TODO: Implement your preferred notification method (email, Slack, etc.)
    
    def _save_monitoring_data(self):
        """Save monitoring data to file"""
        monitoring_file = os.path.join(self.output_dir, 'monitoring_data.json')
        with open(monitoring_file, 'w') as f:
            json.dump(self.monitoring_data, f, indent=2)
        
    def get_monitoring_metrics(self, time_range: str = '24h') -> Dict[str, Any]:
        """Get monitoring metrics for specified time range"""
        current_time = datetime.now()
        metrics = {
            'average_vulnerability_score': 0,
            'max_vulnerability_score': 0,
            'alert_count': 0,
            'risk_trend': []
        }
        
        # Filter data based on time range
        filtered_data = [
            entry for entry in self.monitoring_data
            if (current_time - datetime.fromisoformat(entry['timestamp'])).total_seconds() <= 
            self._parse_time_range(time_range)
        ]
        
        if filtered_data:
            scores = [entry['total_vulnerability_score'] for entry in filtered_data]
            metrics['average_vulnerability_score'] = sum(scores) / len(scores)
            metrics['max_vulnerability_score'] = max(scores)
            metrics['risk_trend'] = [
                {'timestamp': entry['timestamp'], 'score': entry['total_vulnerability_score']}
                for entry in filtered_data
            ]
        
        return metrics
    
    def _parse_time_range(self, time_range: str) -> float:
        """Convert time range string to seconds"""
        unit = time_range[-1]
        value = float(time_range[:-1])
        
        if unit == 'h':
            return value * 3600
        elif unit == 'd':
            return value * 86400
        elif unit == 'w':
            return value * 604800
        raise ValueError(f'Invalid time range format: {time_range}')