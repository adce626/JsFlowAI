"""
Utility functions for JSFlow AI
"""

import os
import re
import logging
import jsbeautifier
from datetime import datetime
from colorama import Fore, Style

# Global logger
logger = None

def setup_logging(verbose=False):
    """Setup logging configuration"""
    global logger
    
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Setup logging
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'logs/jsflow_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger('JSFlowAI')

def log_info(message):
    """Log info message with color"""
    if logger:
        logger.info(message)
    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")

def log_warning(message):
    """Log warning message with color"""
    if logger:
        logger.warning(message)
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")

def log_error(message):
    """Log error message with color"""
    if logger:
        logger.error(message)
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

def beautify_js(js_content):
    """Beautify JavaScript code for better analysis"""
    try:
        options = jsbeautifier.default_options()
        options.indent_size = 2
        options.space_in_empty_paren = True
        options.jslint_happy = True
        options.keep_array_indentation = True
        
        beautified = jsbeautifier.beautify(js_content, options)
        return beautified
    except Exception as e:
        log_warning(f"Failed to beautify JavaScript: {str(e)}")
        return js_content

def generate_html_report(results):
    """Generate HTML report from analysis results"""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSFlow AI - Security Analysis Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .card-header { background-color: #f8f9fa; }
        .code-snippet { background-color: #f8f9fa; font-family: 'Courier New', monospace; }
        .vulnerability-card { margin-bottom: 1rem; }
        .attack-vector { background-color: #fff3cd; }
        .recommendation { background-color: #d1ecf1; }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <div class="row">
            <div class="col-12">
                <h1 class="mb-4">
                    <i class="fas fa-shield-alt"></i> JSFlow AI Security Analysis Report
                </h1>
                <p class="text-muted">Generated on {timestamp}</p>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-12">
                {summary_cards}
            </div>
        </div>
        
        <div class="row">
            <div class="col-12">
                {file_analyses}
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    
    # Generate summary cards
    total_files = len(results)
    total_vulnerabilities = sum(len(r.get('ai_analysis', {}).get('vulnerabilities', [])) for r in results if 'error' not in r)
    total_endpoints = sum(len(r.get('parsing_results', {}).get('endpoints', [])) for r in results if 'error' not in r)
    total_secrets = sum(len(r.get('parsing_results', {}).get('secrets', [])) for r in results if 'error' not in r)
    
    summary_cards = f"""
    <div class="row">
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title"><i class="fas fa-file-code"></i> Files</h5>
                    <h2 class="text-primary">{total_files}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title"><i class="fas fa-exclamation-triangle"></i> Vulnerabilities</h5>
                    <h2 class="text-danger">{total_vulnerabilities}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title"><i class="fas fa-globe"></i> Endpoints</h5>
                    <h2 class="text-info">{total_endpoints}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title"><i class="fas fa-key"></i> Secrets</h5>
                    <h2 class="text-warning">{total_secrets}</h2>
                </div>
            </div>
        </div>
    </div>
    """
    
    # Generate file analyses
    file_analyses = ""
    for result in results:
        if 'error' in result:
            file_analyses += f"""
            <div class="card mb-4">
                <div class="card-header">
                    <h5><i class="fas fa-exclamation-circle text-danger"></i> {os.path.basename(result['file_path'])}</h5>
                </div>
                <div class="card-body">
                    <div class="alert alert-danger">
                        <strong>Error:</strong> {result['error']}
                    </div>
                </div>
            </div>
            """
            continue
        
        file_path = result['file_path']
        parsing_results = result.get('parsing_results', {})
        ai_analysis = result.get('ai_analysis', {})
        data_flow_analysis = result.get('data_flow_analysis', {})
        
        # File header
        file_analyses += f"""
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="fas fa-file-code"></i> {os.path.basename(file_path)}</h5>
                <small class="text-muted">{file_path}</small>
            </div>
            <div class="card-body">
        """
        
        # Security score
        if ai_analysis.get('security_score'):
            score = ai_analysis['security_score']
            score_color = 'success' if score >= 80 else 'warning' if score >= 60 else 'danger'
            file_analyses += f"""
            <div class="mb-3">
                <h6>Security Score</h6>
                <div class="progress">
                    <div class="progress-bar bg-{score_color}" style="width: {score}%">{score}/100</div>
                </div>
            </div>
            """
        
        # Vulnerabilities
        vulnerabilities = ai_analysis.get('vulnerabilities', [])
        if vulnerabilities:
            file_analyses += '<h6><i class="fas fa-bug"></i> Vulnerabilities</h6>'
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low')
                file_analyses += f"""
                <div class="card vulnerability-card">
                    <div class="card-body">
                        <h6 class="severity-{severity}">
                            <i class="fas fa-exclamation-triangle"></i> {vuln.get('type', 'Unknown')}
                            <span class="badge bg-{get_severity_color(severity)}">{severity.upper()}</span>
                        </h6>
                        <p>{vuln.get('description', 'No description')}</p>
                        {f"<small><strong>Location:</strong> {vuln.get('location', 'Unknown')}</small>" if vuln.get('location') else ""}
                        {f"<br><small><strong>CWE:</strong> {vuln.get('cwe_id', 'N/A')}</small>" if vuln.get('cwe_id') else ""}
                    </div>
                </div>
                """
        
        # Attack vectors
        attack_vectors = ai_analysis.get('attack_vectors', [])
        if attack_vectors:
            file_analyses += '<h6><i class="fas fa-crosshairs"></i> Attack Vectors</h6>'
            for attack in attack_vectors:
                file_analyses += f"""
                <div class="card attack-vector">
                    <div class="card-body">
                        <h6>{attack.get('attack_type', 'Unknown Attack')}</h6>
                        <p>{attack.get('method', 'No method specified')}</p>
                        {f"<code>{attack.get('payload', '')}</code>" if attack.get('payload') else ""}
                    </div>
                </div>
                """
        
        # Endpoints
        endpoints = parsing_results.get('endpoints', [])
        if endpoints:
            file_analyses += f'<h6><i class="fas fa-globe"></i> API Endpoints ({len(endpoints)})</h6>'
            file_analyses += '<ul class="list-group mb-3">'
            for endpoint in endpoints[:10]:  # Show first 10
                file_analyses += f'<li class="list-group-item"><code>{endpoint}</code></li>'
            if len(endpoints) > 10:
                file_analyses += f'<li class="list-group-item text-muted">... and {len(endpoints) - 10} more</li>'
            file_analyses += '</ul>'
        
        # Secrets
        secrets = parsing_results.get('secrets', [])
        if secrets:
            file_analyses += f'<h6><i class="fas fa-key"></i> Potential Secrets ({len(secrets)})</h6>'
            file_analyses += '<div class="table-responsive">'
            file_analyses += '<table class="table table-sm">'
            file_analyses += '<thead><tr><th>Type</th><th>Value (masked)</th><th>Line</th></tr></thead><tbody>'
            for secret in secrets[:5]:  # Show first 5
                masked_value = secret.get('value', '')[:4] + '*' * (len(secret.get('value', '')) - 4)
                file_analyses += f"""
                <tr>
                    <td><span class="badge bg-warning">{secret.get('type', 'Unknown')}</span></td>
                    <td><code>{masked_value}</code></td>
                    <td>{secret.get('line', 'N/A')}</td>
                </tr>
                """
            if len(secrets) > 5:
                file_analyses += f'<tr><td colspan="3" class="text-muted">... and {len(secrets) - 5} more</td></tr>'
            file_analyses += '</tbody></table></div>'
        
        # Data Flow Analysis
        dangerous_flows = data_flow_analysis.get('dangerous_flows', [])
        if dangerous_flows:
            file_analyses += f'<h6><i class="fas fa-sitemap"></i> Data Flow Analysis ({len(dangerous_flows)} flows)</h6>'
            for flow in dangerous_flows[:3]:  # Show first 3 flows
                risk_color = 'danger' if flow.get('risk_level') == 'HIGH' else 'warning' if flow.get('risk_level') == 'MEDIUM' else 'info'
                file_analyses += f"""
                <div class="card mb-2">
                    <div class="card-body">
                        <h6 class="text-{risk_color}">
                            <i class="fas fa-flow-chart"></i> {flow.get('source_type', '').title()} → {flow.get('sink_type', '').title()}
                            <span class="badge bg-{risk_color}">{flow.get('risk_level', 'LOW')}</span>
                        </h6>
                        <p><small>Source: Line {flow.get('source_line', 'N/A')} | Sink: Line {flow.get('sink_line', 'N/A')}</small></p>
                    </div>
                </div>
                """
            if len(dangerous_flows) > 3:
                file_analyses += f'<p class="text-muted">... and {len(dangerous_flows) - 3} more flows</p>'
        
        file_analyses += '</div></div>'  # Close card-body and card
    
    # Replace placeholders
    html_content = html_template.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary_cards=summary_cards,
        file_analyses=file_analyses
    )
    
    return html_content

def get_severity_color(severity):
    """Get Bootstrap color class for severity"""
    color_map = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    }
    return color_map.get(severity.lower(), 'secondary')

def sanitize_filename(filename):
    """Sanitize filename for safe file system usage"""
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def extract_code_snippet(content, line_number, context_lines=3):
    """Extract code snippet around a specific line"""
    lines = content.split('\n')
    start_line = max(0, line_number - context_lines - 1)
    end_line = min(len(lines), line_number + context_lines)
    
    snippet_lines = []
    for i in range(start_line, end_line):
        line_num = i + 1
        line_content = lines[i] if i < len(lines) else ""
        marker = ">>> " if line_num == line_number else "    "
        snippet_lines.append(f"{marker}{line_num:4d}: {line_content}")
    
    return '\n'.join(snippet_lines)

def is_minified_js(content):
    """Check if JavaScript content appears to be minified"""
    lines = content.split('\n')
    
    # If most lines are very long, it's likely minified
    long_lines = sum(1 for line in lines if len(line) > 120)
    
    if len(lines) > 0 and long_lines / len(lines) > 0.5:
        return True
    
    # Check for lack of whitespace
    total_chars = len(content)
    whitespace_chars = content.count(' ') + content.count('\t') + content.count('\n')
    
    if total_chars > 0 and whitespace_chars / total_chars < 0.1:
        return True
    
    return False

def validate_js_syntax(content):
    """Basic JavaScript syntax validation"""
    # Count brackets, braces, and parentheses
    brackets = {'(': 0, '[': 0, '{': 0}
    closing = {')', ']', '}'}
    
    for char in content:
        if char in brackets:
            brackets[char] += 1
        elif char in closing:
            if char == ')':
                brackets['('] -= 1
            elif char == ']':
                brackets['['] -= 1
            elif char == '}':
                brackets['{'] -= 1
    
    # Check if all brackets are balanced
    unbalanced = [k for k, v in brackets.items() if v != 0]
    
    return {
        'is_valid': len(unbalanced) == 0,
        'unbalanced_brackets': unbalanced,
        'syntax_errors': []
    }
