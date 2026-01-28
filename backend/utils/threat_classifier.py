"""
Machine learning-based threat classification module
"""
import numpy as np
from sklearn.preprocessing import StandardScaler
import logging
import pickle
from pathlib import Path
import google.generativeai as genai
from datetime import datetime

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """ML-based threat classification system with AI enhancement"""
    
    def __init__(self, gemini_api_key=None):
        self.threat_categories = {
            'malware': {
                'keywords': ['executable', 'dll', 'exe', 'virus', 'trojan', 'ransomware'],
                'severity_base': 9,
                'description': 'Malicious software detected'
            },
            'sql_injection': {
                'keywords': ["' OR", 'UNION SELECT', 'DROP TABLE', 'INSERT INTO', 'DELETE FROM'],
                'severity_base': 8,
                'description': 'SQL injection attack detected'
            },
            'xss': {
                'keywords': ['<script>', 'javascript:', 'onerror', 'onload', 'eval('],
                'severity_base': 7,
                'description': 'Cross-site scripting detected'
            },
            'ddos': {
                'keywords': ['syn flood', 'udp flood', 'icmp flood', 'slowloris', 'amplification'],
                'severity_base': 9,
                'description': 'Distributed denial of service attack'
            },
            'brute_force': {
                'keywords': ['login attempt', 'password', 'authentication fail', 'ssh attempt'],
                'severity_base': 6,
                'description': 'Brute force attack detected'
            },
            'privilege_escalation': {
                'keywords': ['sudo', 'setuid', 'capability', 'kernel exploit', 'admin'],
                'severity_base': 9,
                'description': 'Privilege escalation attempt'
            },
            'data_exfiltration': {
                'keywords': ['upload', 'exfil', 'large transfer', 'tunnel', 'encrypted channel'],
                'severity_base': 8,
                'description': 'Data exfiltration detected'
            },
            'command_injection': {
                'keywords': [';', '&&', '|', '`', '$(',  'bash', 'shell', 'cmd'],
                'severity_base': 8,
                'description': 'Command injection detected'
            },
            'path_traversal': {
                'keywords': ['../', '..\\', 'directory traversal', '/etc/passwd', 'windows/system32'],
                'severity_base': 7,
                'description': 'Path traversal attack'
            },
            'csrf': {
                'keywords': ['csrf', 'cross-site request', 'unauthorized action'],
                'severity_base': 6,
                'description': 'Cross-site request forgery'
            },
            'reconnaissance': {
                'keywords': ['scan', 'probe', 'fingerprint', 'nmap', 'enum', 'recon'],
                'severity_base': 4,
                'description': 'Network reconnaissance'
            },
            'anomaly': {
                'keywords': ['unusual', 'abnormal', 'outlier', 'deviation'],
                'severity_base': 5,
                'description': 'Anomalous activity detected'
            }
        }
        
        self.scaler = StandardScaler()
        self.gemini_api_key = gemini_api_key
        self.gemini_enabled = False
        
        # Initialize Gemini if API key provided
        if gemini_api_key:
            try:
                genai.configure(api_key=gemini_api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                self.gemini_enabled = True
                logger.info("Gemini API initialized for threat classification")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini API: {e}")
                self.gemini_enabled = False
    
    def classify(self, threat_data):
        """
        Classify threat and determine severity and confidence
        Uses Gemini AI if available for enhanced classification
        
        Args:
            threat_data: Threat data (dict or string)
            
        Returns:
            Classification result with type, severity, and confidence
        """
        if isinstance(threat_data, dict):
            payload = str(threat_data.get('payload', '')) + str(threat_data.get('data', ''))
            source_ip = threat_data.get('source_ip', 'N/A')
            dest_ip = threat_data.get('destination_ip', 'N/A')
        else:
            payload = str(threat_data)
            source_ip = 'N/A'
            dest_ip = 'N/A'
        
        # Try Gemini classification first if enabled
        if self.gemini_enabled and payload and payload.strip():
            gemini_result = self._classify_with_gemini(payload, source_ip, dest_ip)
            if gemini_result and gemini_result['type'] != 'unknown':
                return gemini_result
        
        # Fallback to traditional classification
        features = self._extract_features(payload, threat_data if isinstance(threat_data, dict) else {})
        best_match = self._find_best_match(payload)
        confidence = self._calculate_confidence(payload, best_match)
        severity = self._calculate_severity(best_match, features, confidence)
        
        return {
            'type': best_match['type'],
            'category': best_match['category'],
            'severity': severity,
            'confidence': confidence,
            'description': best_match['description'],
            'features': features,
            'risk_level': self._get_risk_level(severity),
            'recommended_action': self._get_recommended_action(best_match['type']),
            'ai_enhanced': False
        }
    
    def _classify_with_gemini(self, payload, source_ip, dest_ip):
        """Classify threat using Gemini AI"""
        try:
            prompt = f"""Analyze this cybersecurity threat data and classify it:

Payload: {payload}
Source IP: {source_ip}
Destination IP: {dest_ip}

Classify into one of these categories: malware, sql_injection, xss, ddos, brute_force, privilege_escalation, data_exfiltration, command_injection, path_traversal, csrf, reconnaissance, or provide a specific threat type if different.

Respond ONLY with JSON (no markdown, no code blocks):
{{
  "type": "threat_type",
  "severity": 1-10,
  "confidence": 0.0-1.0,
  "description": "Brief description"
}}"""
            
            response = self.model.generate_content(prompt, safety_settings=[
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE"
                }
            ])
            
            if response.text:
                import json
                result = json.loads(response.text.strip())
                result['ai_enhanced'] = True
                result['category'] = result.get('type', 'unknown')
                result['risk_level'] = self._get_risk_level(result.get('severity', 5))
                result['recommended_action'] = self._get_recommended_action(result.get('type', 'unknown'))
                return result
        except Exception as e:
            logger.warning(f"Gemini classification failed: {e}")
        
        return None
        
    
    def _find_best_match(self, payload):
        """Find the best matching threat category"""
        payload_lower = payload.lower()
        matches = []
        
        for category, data in self.threat_categories.items():
            match_score = 0
            matched_keywords = []
            
            for keyword in data['keywords']:
                keyword_lower = keyword.lower()
                # Check for exact substring match
                if keyword_lower in payload_lower:
                    match_score += 1
                    matched_keywords.append(keyword)
                # Also check for space-separated word match (more lenient)
                elif ' ' not in keyword_lower and keyword_lower in ' '.join(payload_lower.split()):
                    match_score += 0.5  # Lower score for partial word matches
                    matched_keywords.append(keyword)
            
            if match_score > 0:
                matches.append({
                    'type': category,
                    'category': category,
                    'description': data['description'],
                    'severity_base': data['severity_base'],
                    'match_score': match_score,
                    'matched_keywords': matched_keywords
                })
        
        # Return best match or unknown
        if matches:
            best_match = max(matches, key=lambda x: x['match_score'])
            # Ensure we return meaningful classifications
            if best_match['match_score'] > 0:
                return best_match
        
        # If no keyword matches found, try to classify by payload type
        return self._classify_by_payload_type(payload)
    
    def _classify_by_payload_type(self, payload):
        """Classify threat by analyzing payload structure and type"""
        payload_lower = payload.lower()
        
        # Map common threat keywords to categories for fallback classification
        threat_patterns = {
            'sql_injection': ['union', 'select', 'insert', 'delete', 'drop', 'where', 'order', 'group'],
            'xss': ['<script', '<img', '<svg', 'javascript', 'onerror', 'onload', 'eval', '<iframe'],
            'command_injection': ['bash', 'shell', 'cmd', 'powershell', 'whoami', 'chmod', 'ifconfig'],
            'path_traversal': ['../', '..\\', '/etc/', '/windows/', '/system32'],
            'ddos': ['flood', 'syn', 'udp', 'icmp', 'slowloris', 'amplification'],
            'brute_force': ['ssh', 'login', 'password', 'authentication', 'ftp', 'attempt'],
            'malware': ['trojan', 'virus', 'ransomware', 'backdoor', 'keylogger', 'executable', 'dll'],
            'privilege_escalation': ['sudo', 'setuid', 'exploit', 'kernel', 'privilege'],
            'data_exfiltration': ['exfil', 'transfer', 'tunnel', 'upload', 'download'],
            'reconnaissance': ['scan', 'nmap', 'probe', 'fingerprint', 'enum', 'recon']
        }
        
        for threat_type, patterns in threat_patterns.items():
            for pattern in patterns:
                if pattern in payload_lower:
                    return {
                        'type': threat_type,
                        'category': threat_type,
                        'description': self.threat_categories.get(threat_type, {}).get('description', f'{threat_type} detected'),
                        'severity_base': self.threat_categories.get(threat_type, {}).get('severity_base', 5),
                        'match_score': 1,
                        'matched_keywords': [pattern]
                    }
        
        # Ultimate fallback - classify as anomaly based on characteristics
        if len(payload) > 1000 or payload_lower.count(' ') < 3:
            return {
                'type': 'anomaly',
                'category': 'anomaly',
                'description': 'Anomalous activity detected',
                'severity_base': 5,
                'match_score': 0.5,
                'matched_keywords': []
            }
        
        return {
            'type': 'unknown',
            'category': 'unknown',
            'description': 'Unknown threat detected',
            'severity_base': 3,
            'match_score': 0,
            'matched_keywords': []
        }
    
    def _extract_features(self, payload, metadata):
        """Extract statistical features from payload"""
        return {
            'payload_length': len(payload),
            'entropy': self._calculate_entropy(payload),
            'has_unicode': self._has_unicode(payload),
            'has_base64': self._has_base64(payload),
            'has_hex': self._has_hex(payload),
            'suspicious_patterns': self._count_suspicious_patterns(payload),
            'null_bytes': payload.count('\x00'),
            'avg_word_length': self._avg_word_length(payload),
            'port_number': metadata.get('destination_port', 0),
            'protocol_type': metadata.get('protocol', 'unknown')
        }
    
    def _calculate_entropy(self, payload):
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0
        
        # Calculate byte frequency
        byte_counts = {}
        for byte in payload:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(payload)
        for count in byte_counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy / 8  # Normalize to 0-1
    
    def _has_unicode(self, payload):
        """Check if payload contains unicode characters"""
        try:
            payload.encode('ascii')
            return 0
        except UnicodeEncodeError:
            return 1
    
    def _has_base64(self, payload):
        """Check if payload contains base64"""
        import re
        base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
        segments = payload.split()
        for segment in segments:
            if len(segment) > 16 and re.match(base64_pattern, segment):
                return 1
        return 0
    
    def _has_hex(self, payload):
        """Check if payload contains hex encoding"""
        import re
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        return 1 if re.search(hex_pattern, payload) else 0
    
    def _count_suspicious_patterns(self, payload):
        """Count suspicious patterns in payload"""
        patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'popen\s*\(',
            r'\$_\[',
            r'\$_GET',
            r'\$_POST',
            r'base64_decode',
            r'preg_replace\s*\(',
        ]
        
        import re
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, payload, re.IGNORECASE))
        
        return count
    
    def _avg_word_length(self, payload):
        """Calculate average word length"""
        words = payload.split()
        if not words:
            return 0
        return sum(len(w) for w in words) / len(words)
    
    def _calculate_confidence(self, payload, best_match):
        """Calculate confidence score"""
        if best_match['type'] == 'unknown':
            return 0.2
        
        # Base confidence from keyword matches
        base_confidence = min(best_match['match_score'] / 3.0, 1.0)
        
        # Additional confidence from features
        if len(payload) > 100:
            base_confidence += 0.1
        
        if base_confidence > 1.0:
            base_confidence = 1.0
        
        return float(base_confidence)
    
    def _calculate_severity(self, best_match, features, confidence):
        """Calculate severity score (1-10)"""
        severity = best_match['severity_base']
        
        # Adjust based on payload characteristics
        if features['entropy'] > 0.7:
            severity += 1
        
        if features['suspicious_patterns'] > 2:
            severity += 1
        
        # Reduce severity for low confidence
        severity = int(severity * confidence)
        
        # Ensure severity is in range
        return max(1, min(10, severity))
    
    def _get_risk_level(self, severity):
        """Get risk level based on severity"""
        if severity >= 9:
            return 'CRITICAL'
        elif severity >= 7:
            return 'HIGH'
        elif severity >= 5:
            return 'MEDIUM'
        elif severity >= 3:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _get_recommended_action(self, threat_type):
        """Get recommended action for threat type"""
        actions = {
            'malware': ['Isolate infected system', 'Scan with antivirus', 'Block IP address'],
            'sql_injection': ['Block request', 'Patch application', 'Review database logs'],
            'xss': ['Sanitize input', 'Update WAF rules', 'Review client-side code'],
            'ddos': ['Activate DDoS mitigation', 'Block source IPs', 'Enable rate limiting'],
            'brute_force': ['Enable account lockout', 'Implement CAPTCHA', 'Review authentication logs'],
            'privilege_escalation': ['Kill suspicious process', 'Review privilege assignments', 'Apply patches'],
            'data_exfiltration': ['Block outbound connection', 'Inspect data', 'Alert security team'],
            'command_injection': ['Block request', 'Patch vulnerable code', 'Review logs'],
            'unknown': ['Monitor', 'Investigate', 'Alert security team']
        }
        
        return actions.get(threat_type, ['Monitor and investigate'])
    
    def batch_classify(self, threat_list):
        """Classify multiple threats"""
        return [self.classify(threat) for threat in threat_list]
    
    def get_threat_statistics(self, classified_threats):
        """Get statistics from classified threats"""
        if not classified_threats:
            return {}
        
        types = {}
        severities = []
        
        for threat in classified_threats:
            t_type = threat.get('type')
            types[t_type] = types.get(t_type, 0) + 1
            severities.append(threat.get('severity', 0))
        
        return {
            'total_threats': len(classified_threats),
            'threat_types': types,
            'avg_severity': np.mean(severities) if severities else 0,
            'max_severity': max(severities) if severities else 0,
            'min_severity': min(severities) if severities else 0
        }
