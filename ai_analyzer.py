"""
AI Analyzer Module
Uses OpenAI GPT to analyze JavaScript code and identify security vulnerabilities
"""

import json
import os
from datetime import datetime
from openai import OpenAI
from utils import log_info, log_error, log_warning

class AIAnalyzer:
    def __init__(self):
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        self.model = "gpt-4o"
        
        # Initialize OpenAI client
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            log_warning("OPENAI_API_KEY not found in environment variables")
            self.enabled = False
            self.client = None
        else:
            self.client = OpenAI(api_key=api_key)
            self.enabled = True
            log_info("AI Analyzer initialized with OpenAI API")
    
    def analyze_code(self, js_content, parsing_results):
        """Analyze JavaScript code using AI for security vulnerabilities"""
        if not self.enabled or self.client is None:
            log_warning("AI analysis disabled - no API key or explicitly disabled")
            return {
                'enabled': False,
                'vulnerabilities': [],
                'attack_vectors': [],
                'security_score': 0,
                'recommendations': []
            }
        
        try:
            # Prepare analysis prompt
            analysis_prompt = self._create_analysis_prompt(js_content, parsing_results)
            
            log_info("Sending code to AI for security analysis...")
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                response_format={"type": "json_object"},
                max_tokens=2000,
                temperature=0.1  # Low temperature for consistent security analysis
            )
            
            # Parse AI response
            response_content = response.choices[0].message.content
            if response_content is None:
                raise ValueError("Empty response from OpenAI API")
            ai_response = json.loads(response_content)
            
            # Post-process the response
            processed_analysis = self._process_ai_response(ai_response, parsing_results)
            
            log_info(f"AI analysis complete - found {len(processed_analysis['vulnerabilities'])} vulnerabilities")
            
            return processed_analysis
            
        except Exception as e:
            log_error(f"AI analysis failed: {str(e)}")
            return {
                'enabled': True,
                'error': str(e),
                'vulnerabilities': [],
                'attack_vectors': [],
                'security_score': 0,
                'recommendations': []
            }
    
    def _get_system_prompt(self):
        """Get the system prompt for AI analysis"""
        return """You are a cybersecurity expert specializing in JavaScript security analysis. 

Your task is to analyze JavaScript code for security vulnerabilities and potential attack vectors.

Focus on:
1. Common web vulnerabilities (XSS, CSRF, injection attacks)
2. Insecure coding practices
3. Exposed sensitive data
4. Authentication/authorization issues
5. Client-side security weaknesses

Respond ONLY with valid JSON in this exact format:
{
    "vulnerabilities": [
        {
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low",
            "description": "detailed description",
            "location": "function/line reference",
            "cwe_id": "CWE-XXX",
            "impact": "potential impact description"
        }
    ],
    "attack_vectors": [
        {
            "attack_type": "attack category",
            "method": "how to exploit",
            "payload": "example payload or technique",
            "target": "what part of code to target"
        }
    ],
    "security_score": 85,
    "recommendations": [
        {
            "priority": "high|medium|low",
            "action": "specific remediation step",
            "reason": "why this is important"
        }
    ],
    "code_quality": {
        "uses_eval": false,
        "has_xss_risks": true,
        "exposes_sensitive_data": false,
        "has_insecure_communication": false
    }
}"""
    
    def _create_analysis_prompt(self, js_content, parsing_results):
        """Create analysis prompt for AI"""
        # Truncate content if too long (keep first 3000 chars)
        truncated_content = js_content[:3000] + "..." if len(js_content) > 3000 else js_content
        
        prompt = f"""Analyze this JavaScript code for security vulnerabilities:

## JavaScript Code:
```javascript
{truncated_content}
```

## Parsing Results Found:
- Endpoints: {len(parsing_results.get('endpoints', []))} found
- Secrets: {len(parsing_results.get('secrets', []))} found  
- Suspicious Functions: {len(parsing_results.get('suspicious_functions', []))} found

## Detailed Findings:
{self._format_parsing_results(parsing_results)}

Please provide a comprehensive security analysis focusing on:
1. Real vulnerabilities and their severity
2. Practical attack vectors with specific methods
3. Actionable security recommendations
4. Overall security score (0-100)

Respond with valid JSON only."""
        
        return prompt
    
    def _format_parsing_results(self, parsing_results):
        """Format parsing results for prompt"""
        formatted = []
        
        if parsing_results.get('endpoints'):
            formatted.append("### Endpoints:")
            for endpoint in parsing_results['endpoints'][:5]:  # Show first 5
                formatted.append(f"- {endpoint}")
                
        if parsing_results.get('secrets'):
            formatted.append("### Potential Secrets:")
            for secret in parsing_results['secrets'][:3]:  # Show first 3
                formatted.append(f"- {secret.get('type', 'Unknown')}: {secret.get('value', '')[:10]}...")
                
        if parsing_results.get('suspicious_functions'):
            formatted.append("### Suspicious Functions:")
            for func in parsing_results['suspicious_functions'][:3]:
                formatted.append(f"- {func.get('match', '')} at line {func.get('line', 'unknown')}")
        
        return '\n'.join(formatted) if formatted else "No specific patterns detected"
    
    def _process_ai_response(self, ai_response, parsing_results):
        """Post-process AI response and add metadata"""
        processed = {
            'enabled': True,
            'model_used': self.model,
            'vulnerabilities': ai_response.get('vulnerabilities', []),
            'attack_vectors': ai_response.get('attack_vectors', []),
            'security_score': ai_response.get('security_score', 0),
            'recommendations': ai_response.get('recommendations', []),
            'code_quality': ai_response.get('code_quality', {}),
            'parsing_summary': {
                'endpoints_count': len(parsing_results.get('endpoints', [])),
                'secrets_count': len(parsing_results.get('secrets', [])),
                'suspicious_functions_count': len(parsing_results.get('suspicious_functions', []))
            }
        }
        
        # Add severity counts
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in processed['vulnerabilities']:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        processed['severity_distribution'] = severity_counts
        
        return processed
    
    def get_timestamp(self):
        """Get current timestamp"""
        return datetime.now().isoformat()
