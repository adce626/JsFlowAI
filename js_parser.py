"""
JavaScript Parser Module
Extracts security-relevant patterns from JavaScript code using regex
"""

import re
import json
from urllib.parse import urlparse
from utils import log_info, log_warning

class JSParser:
    def __init__(self):
        # Regex patterns for security analysis
        self.patterns = {
            'endpoints': [
                r'["\']([/][^"\']*)["\']',  # URL paths
                r'fetch\s*\(\s*["\']([^"\']+)["\']',  # fetch() calls
                r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',  # axios calls
                r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',  # HTTP method calls
                r'XMLHttpRequest.*?open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',  # XMLHttpRequest
                r'url\s*:\s*["\']([^"\']+)["\']',  # URL property
                r'endpoint\s*:\s*["\']([^"\']+)["\']',  # endpoint property
                r'api\s*[+]\s*["\']([^"\']+)["\']',  # API concatenation
            ],
            
            'secrets': [
                # API Keys and Tokens
                r'["\'][A-Za-z0-9]{20,}["\']',  # Generic long strings
                r'api[_-]?key["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]+)',  # API keys
                r'secret[_-]?key["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]+)',  # Secret keys
                r'access[_-]?token["\'\s]*[:=]["\'\s]*([A-Za-z0-9._-]+)',  # Access tokens
                r'bearer["\'\s]+([A-Za-z0-9._-]+)',  # Bearer tokens
                r'authorization["\'\s]*[:=]["\'\s]*([A-Za-z0-9._-]+)',  # Authorization headers
                r'x[_-]api[_-]key["\'\s]*[:=]["\'\s]*([A-Za-z0-9._-]+)',  # X-API-Key headers
                
                # JWT Tokens
                r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',  # JWT tokens
                r'jwt["\'\s]*[:=]["\'\s]*([A-Za-z0-9._-]+)',  # JWT variables
                r'token["\'\s]*[:=]["\'\s]*([A-Za-z0-9._-]{20,})',  # Generic tokens
                
                # Cloud Provider Keys
                r'sk_[a-zA-Z0-9]{24,}',  # Stripe secret keys
                r'pk_[a-zA-Z0-9]{24,}',  # Stripe public keys
                r'rk_[a-zA-Z0-9]{24,}',  # Stripe restricted keys
                r'AKIA[0-9A-Z]{16}',  # AWS access keys
                r'ASIA[0-9A-Z]{16}',  # AWS temporary access keys
                r'ya29\.[0-9A-Za-z_-]+',  # Google OAuth
                r'AIza[0-9A-Za-z_-]{35}',  # Google API keys
                r'1\/\/[0-9A-Za-z_-]{43}',  # Google service account
                r'sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}',  # Square OAuth
                
                # GitHub Tokens
                r'ghp_[A-Za-z0-9_]{36}',  # GitHub personal access tokens
                r'gho_[A-Za-z0-9_]{36}',  # GitHub OAuth tokens
                r'ghu_[A-Za-z0-9_]{36}',  # GitHub user-to-server tokens
                r'ghs_[A-Za-z0-9_]{36}',  # GitHub server-to-server tokens
                r'ghr_[A-Za-z0-9_]{36}',  # GitHub refresh tokens
                
                # Other Common Providers
                r'sk_test_[0-9a-zA-Z]{24}',  # Stripe test keys
                r'sk_live_[0-9a-zA-Z]{24}',  # Stripe live keys (CRITICAL!)
                r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',  # SendGrid
                r'key-[0-9a-f]{32}',  # Mailgun
                r'[0-9a-f]{32}-us[0-9]{1,2}',  # Mailchimp
                r'R_[0-9a-f]{32}',  # Rollbar
                r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',  # Slack Bot
                r'xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',  # Slack User
                
                # Hashes (potential tokens)
                r'[0-9a-f]{32}',  # MD5 hashes (potential tokens)
                r'[0-9a-f]{40}',  # SHA1 hashes (potential tokens)
                r'[0-9a-f]{64}',  # SHA256 hashes (potential tokens)
                
                # Database Connection Strings
                r'mongodb://[^"\']*',  # MongoDB connection strings
                r'mysql://[^"\']*',  # MySQL connection strings
                r'postgres://[^"\']*',  # PostgreSQL connection strings
                r'redis://[^"\']*',  # Redis connection strings
            ],
            
            'suspicious_functions': [
                r'eval\s*\(',  # eval() calls
                r'Function\s*\(',  # Function constructor
                r'setTimeout\s*\(["\'][^"\']*["\']',  # setTimeout with string
                r'setInterval\s*\(["\'][^"\']*["\']',  # setInterval with string
                r'document\.write\s*\(',  # document.write
                r'innerHTML\s*=',  # innerHTML assignment
                r'outerHTML\s*=',  # outerHTML assignment
                r'\.appendChild\s*\(',  # appendChild
                r'\.insertAdjacentHTML\s*\(',  # insertAdjacentHTML
                r'location\.href\s*=',  # location.href assignment
                r'window\.open\s*\(',  # window.open
            ],
            
            'sensitive_data': [
                r'password["\'\s]*[:=]',  # Password fields
                r'username["\'\s]*[:=]',  # Username fields
                r'email["\'\s]*[:=]',  # Email fields
                r'ssn["\'\s]*[:=]',  # SSN fields
                r'credit[_-]?card["\'\s]*[:=]',  # Credit card fields
                r'phone["\'\s]*[:=]',  # Phone fields
                r'address["\'\s]*[:=]',  # Address fields
                r'token["\'\s]*[:=]',  # Token fields
                r'session[_-]?id["\'\s]*[:=]',  # Session ID fields
            ],
            
            'dangerous_patterns': [
                r'dangerouslySetInnerHTML',  # React dangerous HTML
                r'v-html\s*=',  # Vue v-html directive
                r'\$\{[^}]*\}',  # Template literals (potential injection)
                r'window\[["\'][^"\']*["\']\]',  # Dynamic window property access
                r'this\[["\'][^"\']*["\']\]',  # Dynamic this property access
                r'localStorage\.setItem',  # localStorage usage
                r'sessionStorage\.setItem',  # sessionStorage usage
                r'document\.cookie\s*=',  # Cookie manipulation
                r'postMessage\s*\(',  # postMessage calls
                r'addEventListener\s*\(\s*["\']message["\']',  # Message event listeners
            ]
        }
    
    def parse(self, js_content, file_path):
        """Parse JavaScript content and extract security-relevant information"""
        results = {
            'file_path': str(file_path),
            'endpoints': [],
            'secrets': [],
            'suspicious_functions': [],
            'sensitive_data': [],
            'dangerous_patterns': [],
            'functions': [],
            'variables': [],
            'imports': [],
            'exports': []
        }
        
        # Extract endpoints
        results['endpoints'] = self._extract_endpoints(js_content)
        
        # Extract potential secrets
        results['secrets'] = self._extract_secrets(js_content)
        
        # Extract suspicious functions
        results['suspicious_functions'] = self._extract_pattern_matches(
            js_content, self.patterns['suspicious_functions'], 'Suspicious Functions'
        )
        
        # Extract sensitive data patterns
        results['sensitive_data'] = self._extract_pattern_matches(
            js_content, self.patterns['sensitive_data'], 'Sensitive Data'
        )
        
        # Extract dangerous patterns
        results['dangerous_patterns'] = self._extract_pattern_matches(
            js_content, self.patterns['dangerous_patterns'], 'Dangerous Patterns'
        )
        
        # Extract functions
        results['functions'] = self._extract_functions(js_content)
        
        # Extract variables
        results['variables'] = self._extract_variables(js_content)
        
        # Extract imports/exports
        results['imports'] = self._extract_imports(js_content)
        results['exports'] = self._extract_exports(js_content)
        
        log_info(f"Extracted {len(results['endpoints'])} endpoints, {len(results['secrets'])} potential secrets")
        
        return results
    
    def _extract_endpoints(self, content):
        """Extract API endpoints and URLs"""
        endpoints = set()
        
        for pattern in self.patterns['endpoints']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1) if match.groups() else match.group(0)
                endpoint = endpoint.strip('"\'')
                
                # Filter out obviously non-API endpoints
                if self._is_valid_endpoint(endpoint):
                    endpoints.add(endpoint)
        
        return list(endpoints)
    
    def _extract_secrets(self, content):
        """Extract potential secrets and API keys"""
        secrets = []
        
        for pattern in self.patterns['secrets']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret = match.group(1) if match.groups() else match.group(0)
                secret = secret.strip('"\'')
                
                # Classify the type of secret
                secret_type = self._classify_secret(secret)
                
                secrets.append({
                    'value': secret,
                    'type': secret_type,
                    'pattern': pattern,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return secrets
    
    def _extract_pattern_matches(self, content, patterns, category):
        """Extract matches for a list of patterns"""
        matches = []
        
        for pattern in patterns:
            regex_matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in regex_matches:
                matches.append({
                    'pattern': pattern,
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end()),
                    'category': category
                })
        
        return matches
    
    def _extract_functions(self, content):
        """Extract function definitions"""
        functions = []
        
        # Function declarations
        func_patterns = [
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*function\s*\([^)]*\)',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\([^)]*\)',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*',
            r'async\s+function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)',
        ]
        
        for pattern in func_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                func_name = match.group(1)
                functions.append({
                    'name': func_name,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return functions
    
    def _extract_variables(self, content):
        """Extract variable declarations"""
        variables = []
        
        var_patterns = [
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                variables.append({
                    'name': var_name,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return variables
    
    def _extract_imports(self, content):
        """Extract import statements"""
        imports = []
        
        import_patterns = [
            r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
            r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
        ]
        
        for pattern in import_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                module = match.group(1)
                imports.append({
                    'module': module,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return imports
    
    def _extract_exports(self, content):
        """Extract export statements"""
        exports = []
        
        export_patterns = [
            r'export\s+(?:default\s+)?(?:function\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)',
            r'module\.exports\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)',
        ]
        
        for pattern in export_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                export_name = match.group(1)
                exports.append({
                    'name': export_name,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return exports
    
    def _is_valid_endpoint(self, endpoint):
        """Check if a string looks like a valid API endpoint"""
        if not endpoint or len(endpoint) < 2:
            return False
        
        # Must start with /
        if not endpoint.startswith('/'):
            return False
        
        # Filter out common false positives
        false_positives = [
            '//',  # Comments
            '/*',  # Comments
            '//',  # Protocol
            '/css',  # Static files
            '/js',   # Static files
            '/img',  # Static files
            '/images',  # Static files
            '/fonts',  # Static files
            '/assets',  # Static files
        ]
        
        for fp in false_positives:
            if endpoint.startswith(fp):
                return False
        
        # Must contain at least one alphanumeric character
        if not re.search(r'[a-zA-Z0-9]', endpoint):
            return False
        
        return True
    
    def _classify_secret(self, secret):
        """Classify the type of secret based on patterns with risk assessment"""
        # Critical Risk Secrets (Production Keys)
        if secret.startswith('sk_live_'):
            return 'Stripe Live Secret Key (CRITICAL)'
        elif secret.startswith('AKIA') and len(secret) == 20:
            return 'AWS Access Key (CRITICAL)'
        elif secret.startswith('ASIA') and len(secret) == 20:
            return 'AWS Temporary Access Key (HIGH)'
        elif secret.startswith('ya29.'):
            return 'Google OAuth Token (HIGH)'
        elif secret.startswith('xoxb-'):
            return 'Slack Bot Token (HIGH)'
        elif secret.startswith('xoxp-'):
            return 'Slack User Token (HIGH)'
        elif secret.startswith('ghp_'):
            return 'GitHub Personal Access Token (HIGH)'
        elif secret.startswith('gho_'):
            return 'GitHub OAuth Token (HIGH)'
        elif secret.startswith('ghs_'):
            return 'GitHub Server Token (HIGH)'
        elif secret.startswith('SG.') and len(secret) > 60:
            return 'SendGrid API Key (HIGH)'
        
        # Medium Risk Secrets
        elif secret.startswith('sk_test_'):
            return 'Stripe Test Secret Key (MEDIUM)'
        elif secret.startswith('pk_'):
            return 'Stripe Public Key (MEDIUM)'
        elif secret.startswith('rk_'):
            return 'Stripe Restricted Key (MEDIUM)'
        elif secret.startswith('AIza'):
            return 'Google API Key (MEDIUM)'
        elif secret.startswith('key-') and len(secret) == 36:
            return 'Mailgun API Key (MEDIUM)'
        elif secret.startswith('R_') and len(secret) == 34:
            return 'Rollbar Access Token (MEDIUM)'
        elif re.match(r'^[0-9a-f]{32}-us[0-9]{1,2}$', secret):
            return 'Mailchimp API Key (MEDIUM)'
        elif secret.startswith('sq0'):
            return 'Square OAuth Token (MEDIUM)'
        
        # JWT Tokens
        elif re.match(r'^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$', secret):
            return 'JWT Token (HIGH)'
            
        # Database Connection Strings
        elif secret.startswith('mongodb://'):
            return 'MongoDB Connection String (CRITICAL)'
        elif secret.startswith('mysql://'):
            return 'MySQL Connection String (CRITICAL)'
        elif secret.startswith('postgres://'):
            return 'PostgreSQL Connection String (CRITICAL)'
        elif secret.startswith('redis://'):
            return 'Redis Connection String (HIGH)'
            
        # Hash patterns
        elif re.match(r'^[0-9a-f]{32}$', secret):
            return 'MD5 Hash/Token (MEDIUM)'
        elif re.match(r'^[0-9a-f]{40}$', secret):
            return 'SHA1 Hash/Token (MEDIUM)'
        elif re.match(r'^[0-9a-f]{64}$', secret):
            return 'SHA256 Hash/Token (MEDIUM)'
            
        # Generic patterns
        elif len(secret) > 30 and any(c.isdigit() for c in secret) and any(c.isalpha() for c in secret):
            return 'Potential API Key (MEDIUM)'
        elif len(secret) > 20:
            return 'Long String Token (LOW)'
        else:
            return 'Unknown Secret (LOW)'
    
    def _get_context(self, content, start, end, context_lines=2):
        """Get surrounding context for a match"""
        lines = content.split('\n')
        match_line = content[:start].count('\n')
        
        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)
        
        context_lines_list = lines[start_line:end_line]
        return '\n'.join(context_lines_list)
