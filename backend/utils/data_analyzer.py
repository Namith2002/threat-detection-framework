"""
Advanced data analysis module for threat intelligence
"""
import json
import re
from collections import Counter
import numpy as np
import logging

logger = logging.getLogger(__name__)


class DataAnalyzer:
    """Advanced threat data analysis and correlation"""
    
    def __init__(self):
        self.threat_cache = {}
        self.correlation_rules = self._setup_correlation_rules()
    
    def _setup_correlation_rules(self):
        """Setup threat correlation rules"""
        return {
            'same_source_multiple_attempts': {
                'description': 'Multiple attack attempts from same source',
                'weight': 0.8
            },
            'sequential_ports': {
                'description': 'Sequential port scanning detected',
                'weight': 0.7
            },
            'large_payload_then_command': {
                'description': 'Large payload followed by command execution',
                'weight': 0.9
            },
            'failed_logins_then_success': {
                'description': 'Brute force followed by successful login',
                'weight': 0.85
            },
            'known_malware_hash': {
                'description': 'Known malware signature detected',
                'weight': 1.0
            }
        }
    
    def analyze(self, data):
        """Comprehensive threat analysis"""
        if isinstance(data, str):
            data = {'payload': data}
        
        analysis = {
            'payload_analysis': self._analyze_payload(data.get('payload', '')),
            'network_analysis': self._analyze_network(data),
            'behavior_analysis': self._analyze_behavior(data),
            'correlation_analysis': self._analyze_correlations(data)
        }
        
        return analysis
    
    def _analyze_payload(self, payload):
        """Analyze payload characteristics"""
        payload_str = str(payload)
        
        return {
            'size': len(payload_str),
            'lines': len(payload_str.split('\n')),
            'words': len(payload_str.split()),
            'unique_chars': len(set(payload_str)),
            'entropy': self._calculate_entropy(payload_str),
            'language': self._detect_language(payload_str),
            'encoding': self._detect_encoding(payload_str),
            'has_shellcode': self._detect_shellcode(payload_str),
            'obfuscation_score': self._calculate_obfuscation_score(payload_str),
            'iocs': self._extract_iocs(payload_str)
        }
    
    def _analyze_network(self, data):
        """Analyze network characteristics"""
        return {
            'source_ip': data.get('source_ip'),
            'destination_ip': data.get('destination_ip'),
            'source_port': data.get('source_port'),
            'destination_port': data.get('destination_port'),
            'protocol': data.get('protocol', 'unknown'),
            'packet_count': data.get('packet_count', 0),
            'byte_count': data.get('byte_count', 0),
            'duration': data.get('duration', 0),
            'data_rate': self._calculate_data_rate(data),
            'flags': self._extract_tcp_flags(data)
        }
    
    def _analyze_behavior(self, data):
        """Analyze behavioral indicators"""
        return {
            'attack_stages': self._identify_attack_stages(data),
            'lateral_movement': self._detect_lateral_movement(data),
            'data_exfiltration': self._detect_exfiltration(data),
            'persistence_indicators': self._detect_persistence(data),
            'c2_indicators': self._detect_c2_communication(data)
        }
    
    def _analyze_correlations(self, data):
        """Analyze threat correlations"""
        correlations = []
        
        source_ip = data.get('source_ip')
        
        # Check correlation rules
        for rule_name, rule in self.correlation_rules.items():
            if self._check_correlation_rule(rule_name, data):
                correlations.append({
                    'rule': rule_name,
                    'description': rule['description'],
                    'weight': rule['weight'],
                    'matched': True
                })
        
        return {
            'correlated_events': correlations,
            'total_weight': sum(c['weight'] for c in correlations),
            'campaign_likelihood': min(sum(c['weight'] for c in correlations), 1.0)
        }
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        byte_counts = Counter(data.encode() if isinstance(data, str) else data)
        entropy = 0
        length = len(data)
        
        for count in byte_counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy / 8
    
    def _detect_language(self, payload):
        """Detect payload language/type"""
        if re.search(r'<\?php|<\?|echo|print', payload, re.IGNORECASE):
            return 'PHP'
        elif re.search(r'#!/bin/|bash|sh|exec', payload, re.IGNORECASE):
            return 'Shell'
        elif re.search(r'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE', payload, re.IGNORECASE):
            return 'SQL'
        elif re.search(r'<script|javascript|eval|function', payload, re.IGNORECASE):
            return 'JavaScript'
        elif re.search(r'python|import|def ', payload, re.IGNORECASE):
            return 'Python'
        else:
            return 'Unknown'
    
    def _detect_encoding(self, payload):
        """Detect payload encoding"""
        encodings = []
        
        if re.search(r'^[A-Za-z0-9+/]+={0,2}$', payload):
            encodings.append('Base64')
        
        if re.search(r'%[0-9A-Fa-f]{2}', payload):
            encodings.append('URL')
        
        if re.search(r'\\x[0-9A-Fa-f]{2}', payload):
            encodings.append('Hex')
        
        if re.search(r'&#\d+;', payload):
            encodings.append('HTML')
        
        return encodings if encodings else ['None']
    
    def _detect_shellcode(self, payload):
        """Detect shellcode patterns"""
        shellcode_patterns = [
            r'\\x90\\x90',  # NOP sled
            r'\\xeb',  # Short jump
            r'\\x55\\x89\\xe5',  # Function prologue
            r'int\s+0x80',  # System call (x86)
            r'syscall',  # System call (x64)
        ]
        
        for pattern in shellcode_patterns:
            if re.search(pattern, payload):
                return True
        
        return False
    
    def _calculate_obfuscation_score(self, payload):
        """Calculate obfuscation score (0-1)"""
        entropy = self._calculate_entropy(payload)
        
        # High entropy and length might indicate obfuscation
        obfuscation_score = min(entropy * len(payload) / 1000, 1.0)
        
        return obfuscation_score
    
    def _extract_iocs(self, payload):
        """Extract Indicators of Compromise (IOCs)"""
        iocs = {
            'emails': re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', payload),
            'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload),
            'urls': re.findall(r'https?://[^\s]+', payload),
            'file_paths': re.findall(r'(?:[a-zA-Z]:\\[\w\\]*|/[\w/]*)', payload),
            'registry_paths': re.findall(r'HKEY_[A-Z_]+\\[^\s]+', payload),
            'hashes': re.findall(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b', payload)
        }
        
        return {k: v for k, v in iocs.items() if v}
    
    def _calculate_data_rate(self, data):
        """Calculate data transmission rate"""
        byte_count = data.get('byte_count', 0)
        duration = data.get('duration', 0)
        
        if duration > 0:
            return byte_count / duration
        return 0
    
    def _extract_tcp_flags(self, data):
        """Extract TCP flags if present"""
        flags = data.get('tcp_flags', '')
        
        flag_meanings = {
            'S': 'SYN',
            'A': 'ACK',
            'F': 'FIN',
            'R': 'RST',
            'P': 'PSH',
            'U': 'URG'
        }
        
        return [flag_meanings.get(f, f) for f in flags]
    
    def _identify_attack_stages(self, data):
        """Identify Cyber Kill Chain stages"""
        stages = []
        payload = str(data.get('payload', ''))
        
        # Reconnaissance
        if any(x in payload.lower() for x in ['scan', 'probe', 'enum', 'info']):
            stages.append('Reconnaissance')
        
        # Weaponization
        if any(x in payload.lower() for x in ['encode', 'pack', 'obfuscate']):
            stages.append('Weaponization')
        
        # Delivery
        if any(x in payload.lower() for x in ['send', 'deliver', 'inject', 'upload']):
            stages.append('Delivery')
        
        # Exploitation
        if any(x in payload.lower() for x in ['exploit', 'vuln', 'bypass', 'overflow']):
            stages.append('Exploitation')
        
        # Installation
        if any(x in payload.lower() for x in ['install', 'persist', 'backdoor', 'rootkit']):
            stages.append('Installation')
        
        # Command & Control
        if any(x in payload.lower() for x in ['c2', 'command', 'control', 'beacon']):
            stages.append('Command & Control')
        
        # Actions on Objectives
        if any(x in payload.lower() for x in ['exfil', 'steal', 'delete', 'encrypt']):
            stages.append('Actions on Objectives')
        
        return stages
    
    def _detect_lateral_movement(self, data):
        """Detect lateral movement indicators"""
        indicators = {
            'internal_scan': False,
            'credential_usage': False,
            'service_exploitation': False,
            'privilege_escalation': False
        }
        
        payload = str(data.get('payload', '')).lower()
        
        if any(x in payload for x in ['192.168', '10.0', '172.16', 'internal']):
            indicators['internal_scan'] = True
        
        if any(x in payload for x in ['password', 'credential', 'auth', 'token']):
            indicators['credential_usage'] = True
        
        if any(x in payload for x in ['service', 'exploit', 'vulnerable', 'weak']):
            indicators['service_exploitation'] = True
        
        if any(x in payload for x in ['privilege', 'admin', 'root', 'sudo']):
            indicators['privilege_escalation'] = True
        
        return indicators
    
    def _detect_exfiltration(self, data):
        """Detect data exfiltration indicators"""
        return {
            'large_transfer': data.get('byte_count', 0) > 10485760,  # > 10MB
            'unusual_port': data.get('destination_port', 0) not in [80, 443, 22, 21, 25, 53],
            'encrypted_tunnel': any(x in str(data.get('payload', '')).lower() for x in ['vpn', 'tor', 'proxy', 'ssh']),
            'outbound_connection': data.get('direction', 'inbound') == 'outbound'
        }
    
    def _detect_persistence(self, data):
        """Detect persistence mechanisms"""
        payload = str(data.get('payload', '')).lower()
        
        return {
            'scheduled_task': 'task scheduler' in payload or 'cron' in payload,
            'registry_modification': 'registry' in payload or 'hkey' in payload,
            'startup_folder': 'startup' in payload or 'autostart' in payload,
            'service_installation': 'service' in payload or 'daemon' in payload,
            'cron_job': 'cron' in payload or 'at command' in payload,
            'webshell': any(x in payload for x in ['<?php', 'aspx', 'jsp', 'webshell']),
            'rootkit': 'rootkit' in payload or 'kernel' in payload
        }
    
    def _detect_c2_communication(self, data):
        """Detect command and control communication"""
        payload = str(data.get('payload', ''))
        
        iocs = self._extract_iocs(payload)
        
        return {
            'suspicious_domains': iocs.get('urls', []),
            'suspicious_ips': iocs.get('ips', []),
            'encoded_communication': self._calculate_obfuscation_score(payload) > 0.7,
            'unusual_protocol': data.get('protocol') not in ['TCP', 'UDP'],
            'dns_tunneling': 'dns' in str(data.get('protocol', '')).lower() and len(iocs.get('domains', [])) > 0
        }
    
    def _check_correlation_rule(self, rule_name, data):
        """Check if correlation rule matches"""
        # Simplified rule checking
        if rule_name == 'same_source_multiple_attempts':
            return data.get('failed_attempts', 0) > 3
        elif rule_name == 'sequential_ports':
            return data.get('port_scan', False)
        elif rule_name == 'large_payload_then_command':
            return data.get('payload_size', 0) > 1000 and 'command' in str(data.get('payload', '')).lower()
        elif rule_name == 'failed_logins_then_success':
            return data.get('failed_attempts', 0) > 0 and data.get('successful_login', False)
        elif rule_name == 'known_malware_hash':
            return data.get('is_known_malware', False)
        
        return False
