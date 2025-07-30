"""
Advanced Data Flow Analysis Module
Tracks variable usage, function calls, and potential security implications
"""

import re
from typing import Dict, List, Set, Tuple
from utils import log_info, log_warning

class DataFlowAnalyzer:
    def __init__(self):
        # Track dangerous data flows
        self.dangerous_sources = {
            'user_input': [
                r'document\.location', r'window\.location', r'location\.href',
                r'location\.search', r'location\.hash', r'window\.name',
                r'document\.referrer', r'document\.URL',
                r'event\.data', r'postMessage', r'localStorage\.getItem',
                r'sessionStorage\.getItem', r'document\.cookie',
                r'URLSearchParams', r'new URL\(', r'decodeURIComponent'
            ],
            'api_data': [
                r'fetch\(', r'axios\.(get|post|put|delete)',
                r'XMLHttpRequest', r'response\.json\(\)',
                r'response\.text\(\)', r'data\.'
            ],
            'form_data': [
                r'FormData', r'form\.' , r'input\.value',
                r'document\.getElementById.*\.value',
                r'document\.querySelector.*\.value'
            ]
        }
        
        self.dangerous_sinks = {
            'dom_manipulation': [
                r'innerHTML\s*=', r'outerHTML\s*=',
                r'document\.write', r'document\.writeln',
                r'insertAdjacentHTML', r'appendChild',
                r'insertBefore', r'replaceChild'
            ],
            'code_execution': [
                r'eval\(', r'Function\(', r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']', r'new Function\('
            ],
            'navigation': [
                r'location\.href\s*=', r'location\.replace',
                r'location\.assign', r'window\.open',
                r'history\.pushState', r'history\.replaceState'
            ],
            'storage': [
                r'localStorage\.setItem', r'sessionStorage\.setItem',
                r'document\.cookie\s*='
            ]
        }
    
    def analyze_data_flow(self, js_content: str, file_path: str) -> Dict:
        """Analyze data flow patterns in JavaScript code"""
        results = {
            'file_path': file_path,
            'data_flows': [],
            'dangerous_flows': [],
            'function_calls': self._extract_function_calls(js_content),
            'variable_flows': self._track_variable_flows(js_content),
            'security_implications': []
        }
        
        # Analyze dangerous data flows
        dangerous_flows = self._find_dangerous_flows(js_content)
        results['dangerous_flows'] = dangerous_flows
        
        # Generate security implications
        security_implications = self._analyze_security_implications(dangerous_flows, js_content)
        results['security_implications'] = security_implications
        
        return results
    
    def _extract_function_calls(self, content: str) -> List[Dict]:
        """Extract function calls and their contexts"""
        function_calls = []
        
        # Pattern to match function calls
        call_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\('
        matches = re.finditer(call_pattern, content)
        
        for match in matches:
            func_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            context = self._get_line_context(content, match.start())
            
            function_calls.append({
                'function': func_name,
                'line': line_num,
                'context': context,
                'position': match.start()
            })
        
        return function_calls
    
    def _track_variable_flows(self, content: str) -> List[Dict]:
        """Track how variables flow through the code"""
        variable_flows = []
        
        # Find variable assignments
        assignment_pattern = r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;]+)'
        assignments = re.finditer(assignment_pattern, content)
        
        for assignment in assignments:
            var_name = assignment.group(1)
            var_value = assignment.group(2).strip()
            line_num = content[:assignment.start()].count('\n') + 1
            
            # Check if this variable is used in dangerous contexts
            dangerous_usage = self._check_dangerous_variable_usage(content, var_name)
            
            variable_flows.append({
                'variable': var_name,
                'assignment': var_value,
                'line': line_num,
                'dangerous_usage': dangerous_usage,
                'context': self._get_line_context(content, assignment.start())
            })
        
        return variable_flows
    
    def _find_dangerous_flows(self, content: str) -> List[Dict]:
        """Find potentially dangerous data flows"""
        dangerous_flows = []
        
        for source_type, source_patterns in self.dangerous_sources.items():
            for sink_type, sink_patterns in self.dangerous_sinks.items():
                flows = self._find_flow_connections(content, source_patterns, sink_patterns)
                
                for flow in flows:
                    dangerous_flows.append({
                        'source_type': source_type,
                        'sink_type': sink_type,
                        'source_pattern': flow['source_pattern'],
                        'sink_pattern': flow['sink_pattern'],
                        'source_line': flow['source_line'],
                        'sink_line': flow['sink_line'],
                        'risk_level': self._assess_flow_risk(source_type, sink_type),
                        'context': flow['context']
                    })
        
        return dangerous_flows
    
    def _find_flow_connections(self, content: str, source_patterns: List[str], sink_patterns: List[str]) -> List[Dict]:
        """Find connections between data sources and sinks"""
        flows = []
        lines = content.split('\n')
        
        # Simple heuristic: look for sources and sinks in nearby lines
        for i, line in enumerate(lines):
            for source_pattern in source_patterns:
                if re.search(source_pattern, line, re.IGNORECASE):
                    # Look for sinks in surrounding lines (within 10 lines)
                    search_start = max(0, i - 5)
                    search_end = min(len(lines), i + 6)
                    
                    for j in range(search_start, search_end):
                        for sink_pattern in sink_patterns:
                            if re.search(sink_pattern, lines[j], re.IGNORECASE):
                                flows.append({
                                    'source_pattern': source_pattern,
                                    'sink_pattern': sink_pattern,
                                    'source_line': i + 1,
                                    'sink_line': j + 1,
                                    'context': f"Source: {line.strip()}\nSink: {lines[j].strip()}"
                                })
        
        return flows
    
    def _check_dangerous_variable_usage(self, content: str, var_name: str) -> List[Dict]:
        """Check if a variable is used in dangerous contexts"""
        dangerous_usage = []
        
        # Look for variable usage in dangerous sinks
        for sink_type, sink_patterns in self.dangerous_sinks.items():
            for pattern in sink_patterns:
                # Create pattern that includes the variable name
                var_pattern = f'{re.escape(var_name)}.*{pattern}|{pattern}.*{re.escape(var_name)}'
                matches = re.finditer(var_pattern, content, re.IGNORECASE)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    dangerous_usage.append({
                        'sink_type': sink_type,
                        'pattern': pattern,
                        'line': line_num,
                        'context': self._get_line_context(content, match.start())
                    })
        
        return dangerous_usage
    
    def _assess_flow_risk(self, source_type: str, sink_type: str) -> str:
        """Assess the risk level of a data flow"""
        high_risk_combinations = [
            ('user_input', 'dom_manipulation'),
            ('user_input', 'code_execution'),
            ('user_input', 'navigation'),
            ('api_data', 'dom_manipulation'),
            ('form_data', 'code_execution')
        ]
        
        medium_risk_combinations = [
            ('user_input', 'storage'),
            ('api_data', 'storage'),
            ('form_data', 'dom_manipulation'),
            ('api_data', 'navigation')
        ]
        
        if (source_type, sink_type) in high_risk_combinations:
            return 'HIGH'
        elif (source_type, sink_type) in medium_risk_combinations:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _analyze_security_implications(self, dangerous_flows: List[Dict], content: str) -> List[Dict]:
        """Analyze security implications of dangerous flows"""
        implications = []
        
        for flow in dangerous_flows:
            source_type = flow['source_type']
            sink_type = flow['sink_type']
            risk_level = flow['risk_level']
            
            implication = {
                'vulnerability_type': self._get_vulnerability_type(source_type, sink_type),
                'risk_level': risk_level,
                'description': self._get_vulnerability_description(source_type, sink_type),
                'attack_vector': self._get_attack_vector(source_type, sink_type),
                'source_line': flow['source_line'],
                'sink_line': flow['sink_line'],
                'remediation': self._get_remediation_advice(source_type, sink_type)
            }
            
            implications.append(implication)
        
        return implications
    
    def _get_vulnerability_type(self, source_type: str, sink_type: str) -> str:
        """Determine vulnerability type based on source and sink"""
        if source_type == 'user_input' and sink_type == 'dom_manipulation':
            return 'DOM-based XSS'
        elif source_type == 'user_input' and sink_type == 'code_execution':
            return 'Code Injection'
        elif source_type == 'user_input' and sink_type == 'navigation':
            return 'Open Redirect'
        elif sink_type == 'storage':
            return 'Data Exposure'
        else:
            return 'Potential Security Issue'
    
    def _get_vulnerability_description(self, source_type: str, sink_type: str) -> str:
        """Get detailed vulnerability description"""
        descriptions = {
            ('user_input', 'dom_manipulation'): 'User input is directly inserted into DOM without sanitization, potentially allowing XSS attacks.',
            ('user_input', 'code_execution'): 'User input is used in code execution contexts (eval, Function), allowing arbitrary code execution.',
            ('user_input', 'navigation'): 'User input controls navigation/redirects without validation, enabling open redirect attacks.',
            ('api_data', 'dom_manipulation'): 'API response data is inserted into DOM without proper validation.',
            ('form_data', 'code_execution'): 'Form data is used in code execution, potentially allowing script injection.'
        }
        
        key = (source_type, sink_type)
        return descriptions.get(key, 'Potential security vulnerability detected in data flow.')
    
    def _get_attack_vector(self, source_type: str, sink_type: str) -> str:
        """Get potential attack vector"""
        vectors = {
            ('user_input', 'dom_manipulation'): 'Inject malicious HTML/JavaScript through URL parameters, hash, or user input fields.',
            ('user_input', 'code_execution'): 'Craft payload that executes arbitrary JavaScript when processed by eval() or similar functions.',
            ('user_input', 'navigation'): 'Manipulate URL parameters to redirect users to malicious sites.',
            ('api_data', 'dom_manipulation'): 'Compromise API to return malicious content that gets rendered in the browser.',
        }
        
        key = (source_type, sink_type)
        return vectors.get(key, 'Exploit the data flow to inject malicious content or behavior.')
    
    def _get_remediation_advice(self, source_type: str, sink_type: str) -> str:
        """Get remediation advice"""
        advice = {
            ('user_input', 'dom_manipulation'): 'Use textContent instead of innerHTML, or implement proper HTML sanitization.',
            ('user_input', 'code_execution'): 'Avoid eval() and dynamic code execution. Use JSON.parse() for data parsing.',
            ('user_input', 'navigation'): 'Validate and whitelist allowed redirect URLs.',
            ('api_data', 'dom_manipulation'): 'Validate and sanitize all API responses before DOM insertion.',
        }
        
        key = (source_type, sink_type)
        return advice.get(key, 'Implement input validation and output encoding.')
    
    def _get_line_context(self, content: str, position: int, context_lines: int = 2) -> str:
        """Get context around a specific position"""
        lines = content.split('\n')
        line_num = content[:position].count('\n')
        
        start_line = max(0, line_num - context_lines)
        end_line = min(len(lines), line_num + context_lines + 1)
        
        context_lines_list = lines[start_line:end_line]
        return '\n'.join(context_lines_list)