"""
Advanced threat detection engine with machine learning models
"""
import json
import numpy as np
from datetime import datetime, timedelta
import logging
import pickle
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Real-time threat detection using multiple detection techniques"""
    
    def __init__(self):
        self.signatures = self._load_threat_signatures()
        self.anomaly_threshold = 0.85
        self.detection_window = timedelta(minutes=5)
        self.threats = []
    
    def _load_threat_signatures(self):
        """Load known threat signatures"""
        return {
            'sql_injection': {
                'patterns': ["' OR '1'='1", 'UNION SELECT', 'DROP TABLE', 'DELETE FROM'],
                'severity': 8,
                'confidence': 0.95
            },
            'xss': {
                'patterns': ['<script>', 'javascript:', 'onerror=', 'onload='],
                'severity': 7,
                'confidence': 0.90
            },
            'ddos': {
                'patterns': ['high_packet_rate', 'syn_flood', 'udp_flood'],
                'severity': 9,
                'confidence': 0.85
            },
            'brute_force': {
                'patterns': ['multiple_failed_logins', 'ssh_attempts', 'ftp_attempts'],
                'severity': 6,
                'confidence': 0.80
            },
            'malware': {
                'patterns': ['executable', 'suspicious_behavior', 'registry_modification'],
                'severity': 9,
                'confidence': 0.88
            },
            'data_exfiltration': {
                'patterns': ['large_outbound_data', 'unusual_port', 'encrypted_tunnel'],
                'severity': 8,
                'confidence': 0.82
            },
            'privilege_escalation': {
                'patterns': ['sudo_abuse', 'kernel_exploit', 'permission_bypass'],
                'severity': 9,
                'confidence': 0.84
            },
            'command_injection': {
                'patterns': [';rm -rf', '&&', '|grep', '`whoami`'],
                'severity': 8,
                'confidence': 0.90
            }
        }
    
    def detect_threats(self, network_data=None):
        """
        Detect threats from network data using multiple techniques
        
        Args:
            network_data: Network packets/flows to analyze
            
        Returns:
            List of detected threats
        """
        detected_threats = []
        
        # If no data provided, generate synthetic data for demo
        if network_data is None:
            network_data = self._generate_sample_traffic()
        
        for data in network_data:
            # Signature-based detection
            sig_threats = self._signature_based_detection(data)
            detected_threats.extend(sig_threats)
            
            # Anomaly-based detection
            anomaly_threats = self._anomaly_based_detection(data)
            detected_threats.extend(anomaly_threats)
            
            # Behavioral-based detection
            behavioral_threats = self._behavioral_detection(data)
            detected_threats.extend(behavioral_threats)
            
            # Heuristic-based detection
            heuristic_threats = self._heuristic_detection(data)
            detected_threats.extend(heuristic_threats)
        
        return detected_threats
    
    def _signature_based_detection(self, data):
        """Signature-based threat detection"""
        threats = []
        payload = data.get('payload', '')
        
        for threat_type, sig_data in self.signatures.items():
            for pattern in sig_data.get('patterns', []):
                if pattern.lower() in str(payload).lower():
                    threats.append({
                        'id': f"sig_{datetime.now().timestamp()}",
                        'type': 'signature',
                        'threat_type': threat_type,
                        'source_ip': data.get('source_ip'),
                        'destination_ip': data.get('destination_ip'),
                        'payload': payload,
                        'severity': sig_data.get('severity'),
                        'confidence': sig_data.get('confidence'),
                        'detection_method': 'signature_matching',
                        'matched_pattern': pattern
                    })
        
        return threats
    
    def _anomaly_based_detection(self, data):
        """Anomaly-based threat detection using statistical analysis"""
        threats = []
        
        # Calculate anomaly score based on traffic characteristics
        anomaly_score = self._calculate_anomaly_score(data)
        
        if anomaly_score > self.anomaly_threshold:
            threats.append({
                'id': f"anom_{datetime.now().timestamp()}",
                'type': 'anomaly',
                'threat_type': 'network_anomaly',
                'source_ip': data.get('source_ip'),
                'destination_ip': data.get('destination_ip'),
                'payload': data.get('payload', ''),
                'severity': int(anomaly_score * 10),
                'confidence': anomaly_score,
                'detection_method': 'anomaly_detection',
                'anomaly_score': anomaly_score
            })
        
        return threats
    
    def _behavioral_detection(self, data):
        """Behavioral-based threat detection"""
        threats = []
        
        # Check for suspicious behaviors
        suspicious_behaviors = [
            ('high_packet_rate', data.get('packet_rate', 0) > 1000),
            ('unusual_port', data.get('destination_port', 0) in [0, 65535]),
            ('long_duration', data.get('duration', 0) > 3600),
            ('large_payload', data.get('payload_size', 0) > 10485760),
            ('multiple_failures', data.get('failed_attempts', 0) > 5)
        ]
        
        behavior_score = sum([1 for _, is_suspicious in suspicious_behaviors if is_suspicious]) / len(suspicious_behaviors)
        
        if behavior_score > 0.4:
            threats.append({
                'id': f"beh_{datetime.now().timestamp()}",
                'type': 'behavioral',
                'threat_type': 'suspicious_behavior',
                'source_ip': data.get('source_ip'),
                'destination_ip': data.get('destination_ip'),
                'payload': data.get('payload', ''),
                'severity': int(behavior_score * 10),
                'confidence': behavior_score,
                'detection_method': 'behavioral_analysis',
                'behaviors': [b[0] for b in suspicious_behaviors if b[1]]
            })
        
        return threats
    
    def _heuristic_detection(self, data):
        """Heuristic-based threat detection"""
        threats = []
        
        heuristic_score = 0
        matched_heuristics = []
        
        # Protocol analysis heuristics
        if data.get('protocol') == 'ICMP' and data.get('packet_count', 0) > 1000:
            heuristic_score += 0.3
            matched_heuristics.append('icmp_flood')
        
        # Port-based heuristics
        if data.get('destination_port') in [22, 3389] and data.get('failed_attempts', 0) > 10:
            heuristic_score += 0.4
            matched_heuristics.append('brute_force_attempt')
        
        # Rate-based heuristics
        if data.get('byte_rate', 0) > 100000000:  # 100 Mbps
            heuristic_score += 0.2
            matched_heuristics.append('data_exfiltration')
        
        # Geographical heuristics
        if data.get('is_tor_exit') or data.get('is_proxy'):
            heuristic_score += 0.25
            matched_heuristics.append('anonymization_detected')
        
        if heuristic_score > 0.5:
            threats.append({
                'id': f"heur_{datetime.now().timestamp()}",
                'type': 'heuristic',
                'threat_type': 'heuristic_match',
                'source_ip': data.get('source_ip'),
                'destination_ip': data.get('destination_ip'),
                'payload': data.get('payload', ''),
                'severity': int(heuristic_score * 10),
                'confidence': heuristic_score,
                'detection_method': 'heuristic_analysis',
                'matched_heuristics': matched_heuristics
            })
        
        return threats
    
    def _calculate_anomaly_score(self, data):
        """Calculate anomaly score using statistical methods"""
        features = np.array([
            data.get('packet_rate', 0) / 1000,  # normalized
            data.get('byte_rate', 0) / 10000000,  # normalized
            data.get('failed_attempts', 0) / 10,  # normalized
            1 if data.get('is_encrypted') else 0,
            1 if data.get('is_tor_exit') else 0
        ])
        
        # Simple anomaly calculation (in production, use ML models)
        # Calculate z-score based features
        mean = np.mean(features)
        std = np.std(features) if np.std(features) > 0 else 1
        z_scores = np.abs((features - mean) / std)
        
        anomaly_score = np.mean(z_scores) / 3  # normalize to 0-1
        return min(max(anomaly_score, 0), 1)
    
    def _generate_sample_traffic(self):
        """Generate sample network traffic with realistic threat payloads"""
        import random
        
        ips = [
            '192.168.1.1', '10.0.0.1', '172.16.0.1',
            '203.0.113.45', '198.51.100.89', '192.168.1.100',
            '10.20.30.40', '203.0.113.50'
        ]
        
        # Realistic threat payloads
        payloads = [
            # SQL Injection attempts
            "' OR '1'='1",
            "1' UNION SELECT NULL,NULL,NULL FROM users--",
            "admin'; DROP TABLE users; --",
            "1' OR '1'='1' /*",
            "SELECT * FROM users WHERE username='admin' AND password='' OR 'a'='a",
            
            # XSS attempts
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('XSS vulnerability')",
            "<svg onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            
            # Command injection
            ";cat /etc/passwd",
            "| whoami",
            "&& rm -rf /",
            "`id`",
            "$(whoami)",
            
            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "../../../../../../../../etc/passwd%00.jpg",
            
            # DDoS/Reconnaissance patterns
            "syn_flood_attack",
            "udp_amplification_attempt",
            "nmap_fingerprint",
            "port_scan_detected",
            
            # Brute force patterns
            "ssh_brute_force",
            "ftp_login_attempt_23",
            "multiple_failed_authentication",
            "password_spray_attack",
            
            # Malware signatures
            "win32.trojan.generic",
            "trojan.ransomware.detected",
            "backdoor_shell_access",
            "keylogger_executable",
            
            # Privilege escalation
            "sudo vulnerability exploitation",
            "kernel_exploit_cve_2024_001",
            "privilege escalation attempt",
            
            # Data exfiltration
            "large_data_transfer_outbound",
            "encrypted_tunnel_establishment",
            "data_staging_detected",
            "exfiltration_protocol",
            
            # Anomalous patterns
            "unusual_port_connection",
            "abnormal_traffic_pattern",
            "suspicious_process_injection",
            "rootkit_signature_detected"
        ]
        
        return [
            {
                'source_ip': random.choice(ips),
                'destination_ip': random.choice(ips),
                'destination_port': random.choice([80, 443, 22, 3306, 65535, 8080, 21, 25, 53]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'packet_rate': random.randint(10, 5000),
                'byte_rate': random.randint(1000, 100000000),
                'payload': random.choice(payloads),
                'failed_attempts': random.randint(0, 50),
                'duration': random.randint(1, 7200),
                'packet_count': random.randint(1, 10000),
                'payload_size': random.randint(100, 10485760),
                'is_encrypted': random.choice([True, False]),
                'is_tor_exit': random.choice([True, False, False, False, False])
            }
            for _ in range(random.randint(2, 8))
        ]
    
    def get_system_metrics(self):
        """Get current system performance metrics"""
        import psutil
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            net_io = psutil.net_io_counters()
            
            return {
                'cpu': cpu_percent,
                'memory': memory.percent,
                'network_traffic': net_io.bytes_sent + net_io.bytes_recv
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {str(e)}")
            return {
                'cpu': 0,
                'memory': 0,
                'network_traffic': 0
            }
    
    def export_threats(self, threats, format='json'):
        """Export detected threats in various formats"""
        if format == 'json':
            return json.dumps(threats, indent=2, default=str)
        elif format == 'csv':
            import csv
            from io import StringIO
            output = StringIO()
            if threats:
                writer = csv.DictWriter(output, fieldnames=threats[0].keys())
                writer.writeheader()
                writer.writerows(threats)
            return output.getvalue()
        else:
            return str(threats)
