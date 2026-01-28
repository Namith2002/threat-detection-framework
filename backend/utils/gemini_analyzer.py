"""
Gemini AI-powered threat analysis module
Provides advanced threat analysis and classification using Google's Gemini API
"""
import logging
import json
from typing import Dict, List, Optional
import google.generativeai as genai
from datetime import datetime

logger = logging.getLogger(__name__)


class GeminiThreatAnalyzer:
    """AI-powered threat analysis using Google Gemini"""
    
    def __init__(self, api_key: str, model: str = "gemini-pro"):
        """
        Initialize Gemini threat analyzer
        
        Args:
            api_key: Google Gemini API key
            model: Model name to use (default: gemini-pro)
        """
        self.api_key = api_key
        self.model_name = model
        
        if not api_key:
            logger.warning("Gemini API key not configured. AI analysis will be disabled.")
            self.enabled = False
            return
        
        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(model)
            self.enabled = True
            logger.info(f"Gemini threat analyzer initialized with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
            self.enabled = False
    
    def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze threat using Gemini AI
        
        Args:
            threat_data: Threat information to analyze
            
        Returns:
            Analysis result with enhanced classification and recommendations
        """
        if not self.enabled:
            return self._fallback_analysis(threat_data)
        
        try:
            # Prepare threat context for Gemini
            threat_context = self._format_threat_context(threat_data)
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(threat_context)
            
            # Get Gemini analysis
            response = self.model.generate_content(prompt)
            
            # Parse response
            analysis = self._parse_gemini_response(response.text, threat_data)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Gemini analysis error: {e}")
            return self._fallback_analysis(threat_data)
    
    def batch_analyze_threats(self, threats: List[Dict]) -> List[Dict]:
        """
        Analyze multiple threats
        
        Args:
            threats: List of threat data to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        for threat in threats:
            analysis = self.analyze_threat(threat)
            results.append(analysis)
        return results
    
    def get_mitigation_strategies(self, threat_type: str, threat_data: Dict) -> List[str]:
        """
        Get AI-recommended mitigation strategies
        
        Args:
            threat_type: Type of threat detected
            threat_data: Threat information
            
        Returns:
            List of recommended mitigation strategies
        """
        if not self.enabled:
            return self._default_mitigations(threat_type)
        
        try:
            prompt = f"""
            Given a {threat_type} cybersecurity threat with the following details:
            {json.dumps(threat_data, indent=2)}
            
            Provide 3-5 specific, actionable mitigation strategies that a security team should implement immediately.
            Format as a numbered list.
            """
            
            response = self.model.generate_content(prompt)
            strategies = response.text.strip().split('\n')
            strategies = [s.strip() for s in strategies if s.strip()]
            
            return strategies
            
        except Exception as e:
            logger.error(f"Failed to get mitigations from Gemini: {e}")
            return self._default_mitigations(threat_type)
    
    def generate_threat_report(self, threat_data: Dict, classification: Dict) -> Dict:
        """
        Generate comprehensive threat report
        
        Args:
            threat_data: Raw threat data
            classification: Classification result
            
        Returns:
            Comprehensive threat report
        """
        if not self.enabled:
            return self._basic_report(threat_data, classification)
        
        try:
            prompt = f"""
            Generate a security incident report for the following threat:
            
            Type: {classification.get('type')}
            Severity: {classification.get('severity')}/10
            Confidence: {classification.get('confidence')*100:.1f}%
            Source IP: {threat_data.get('source_ip')}
            Destination IP: {threat_data.get('destination_ip')}
            Timestamp: {threat_data.get('detected_at')}
            
            Provide:
            1. Threat Summary
            2. Impact Assessment
            3. Recommended Actions
            4. Prevention Tips
            
            Keep it concise and technical.
            """
            
            response = self.model.generate_content(prompt)
            
            return {
                'threat_id': threat_data.get('id'),
                'report_generated_at': datetime.utcnow().isoformat(),
                'ai_analysis': response.text,
                'classification': classification,
                'threat_data': threat_data
            }
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return self._basic_report(threat_data, classification)
    
    def _format_threat_context(self, threat_data: Dict) -> str:
        """Format threat data for Gemini analysis"""
        return json.dumps(threat_data, indent=2, default=str)
    
    def _create_analysis_prompt(self, threat_context: str) -> str:
        """Create analysis prompt for Gemini"""
        return f"""
        Analyze the following cybersecurity threat and provide:
        1. Primary threat classification (e.g., malware, DDoS, SQL injection, etc.)
        2. Confidence level (0-100%)
        3. Risk level (CRITICAL, HIGH, MEDIUM, LOW)
        4. Top 3 recommended immediate actions
        5. Root cause analysis
        
        Threat Data:
        {threat_context}
        
        Respond in JSON format with keys: threat_type, confidence, risk_level, actions, root_cause, additional_notes
        """
    
    def _parse_gemini_response(self, response_text: str, threat_data: Dict) -> Dict:
        """Parse Gemini response"""
        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                analysis = self._parse_text_response(response_text)
            
            return {
                'ai_enhanced': True,
                'gemini_analysis': analysis,
                'threat_data': threat_data,
                'analyzed_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to parse Gemini response: {e}")
            return self._fallback_analysis(threat_data)
    
    def _parse_text_response(self, response_text: str) -> Dict:
        """Parse non-JSON response text"""
        return {
            'raw_analysis': response_text,
            'parsed': False
        }
    
    def _fallback_analysis(self, threat_data: Dict) -> Dict:
        """Fallback analysis when Gemini is unavailable"""
        return {
            'ai_enhanced': False,
            'reason': 'Gemini API not available',
            'threat_data': threat_data
        }
    
    def _basic_report(self, threat_data: Dict, classification: Dict) -> Dict:
        """Generate basic report without AI"""
        return {
            'threat_id': threat_data.get('id'),
            'report_generated_at': datetime.utcnow().isoformat(),
            'classification': classification,
            'threat_data': threat_data,
            'ai_enhanced': False
        }
    
    def _default_mitigations(self, threat_type: str) -> List[str]:
        """Default mitigation strategies"""
        mitigations = {
            'malware': [
                'Isolate affected systems immediately',
                'Scan with updated antivirus/antimalware',
                'Block identified malicious IPs/domains',
                'Review and reset compromised credentials'
            ],
            'ddos': [
                'Enable DDoS mitigation service',
                'Block source IPs at perimeter',
                'Implement rate limiting',
                'Activate redundant infrastructure'
            ],
            'sql_injection': [
                'Block malicious requests at WAF',
                'Patch vulnerable application code',
                'Review database logs for unauthorized access',
                'Implement parameterized queries'
            ],
            'xss': [
                'Update Web Application Firewall rules',
                'Patch vulnerable web application',
                'Sanitize user input',
                'Review client-side code for vulnerabilities'
            ],
            'brute_force': [
                'Enable account lockout mechanisms',
                'Implement CAPTCHA challenges',
                'Monitor failed login attempts',
                'Deploy multi-factor authentication'
            ]
        }
        
        return mitigations.get(threat_type, [
            'Monitor threat closely',
            'Investigate affected systems',
            'Review security logs',
            'Implement compensating controls'
        ])
