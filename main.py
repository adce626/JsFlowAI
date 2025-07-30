#!/usr/bin/env python3
"""
JSFlow AI - JavaScript Security Analysis Tool
Main CLI interface for analyzing JavaScript files for security vulnerabilities
"""

import argparse
import os
import sys
import json
from pathlib import Path
from colorama import init, Fore, Style
from tqdm import tqdm

from js_parser import JSParser
from ai_analyzer import AIAnalyzer
from data_flow_analyzer import DataFlowAnalyzer
from utils import beautify_js, generate_html_report, setup_logging, log_info, log_error, log_warning

# Initialize colorama for cross-platform colored output
init()

class JSFlowAI:
    def __init__(self):
        self.parser = JSParser()
        self.ai_analyzer = AIAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.results = []
        
    def analyze_file(self, file_path):
        """Analyze a single JavaScript file"""
        try:
            log_info(f"Analyzing file: {file_path}")
            
            # Read and beautify JavaScript
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                js_content = f.read()
            
            # Beautify the JavaScript for better analysis
            beautified_js = beautify_js(js_content)
            
            # Parse JavaScript for patterns
            parsing_results = self.parser.parse(beautified_js, file_path)
            
            # Data Flow Analysis
            data_flow_analysis = self.data_flow_analyzer.analyze_data_flow(beautified_js, str(file_path))
            
            # AI Analysis
            ai_analysis = self.ai_analyzer.analyze_code(beautified_js, parsing_results)
            
            # Combine results
            result = {
                'file_path': str(file_path),
                'file_size': os.path.getsize(file_path),
                'parsing_results': parsing_results,
                'data_flow_analysis': data_flow_analysis,
                'ai_analysis': ai_analysis,
                'timestamp': self.ai_analyzer.get_timestamp()
            }
            
            return result
            
        except Exception as e:
            log_error(f"Error analyzing {file_path}: {str(e)}")
            return {
                'file_path': str(file_path),
                'error': str(e),
                'timestamp': self.ai_analyzer.get_timestamp()
            }
    
    def analyze_directory(self, directory_path, recursive=True):
        """Analyze all JavaScript files in a directory"""
        js_files = []
        search_pattern = '**/' if recursive else ''
        
        # Support multiple JavaScript file extensions
        extensions = ['*.js', '*.jsx', '*.ts', '*.tsx', '*.vue', '*.mjs']
        
        directory = Path(directory_path)
        for ext in extensions:
            if recursive:
                js_files.extend(directory.rglob(ext))
            else:
                js_files.extend(directory.glob(ext))
        
        # Filter out node_modules and other common exclusions
        excluded_dirs = {'node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'vendor'}
        js_files = [f for f in js_files if not any(excluded in f.parts for excluded in excluded_dirs)]
        
        if not js_files:
            log_warning(f"No JavaScript files found in {directory_path}")
            return []
        
        log_info(f"Found {len(js_files)} JavaScript files (excluding node_modules, dist, etc.)")
        
        # Group files by size for better processing
        small_files = [f for f in js_files if f.stat().st_size < 100000]  # < 100KB
        large_files = [f for f in js_files if f.stat().st_size >= 100000]  # >= 100KB
        
        results = []
        
        # Analyze small files first (usually faster)
        if small_files:
            log_info(f"Processing {len(small_files)} smaller files...")
            for file_path in tqdm(small_files, desc="Analyzing small files"):
                result = self.analyze_file(file_path)
                results.append(result)
        
        # Then analyze larger files
        if large_files:
            log_info(f"Processing {len(large_files)} larger files...")
            for file_path in tqdm(large_files, desc="Analyzing large files"):
                result = self.analyze_file(file_path)
                results.append(result)
            
        return results
    
    def save_results(self, results, output_format, output_path):
        """Save analysis results in specified format"""
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            if output_format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                log_info(f"Results saved to {output_path}")
                
            elif output_format.lower() == 'html':
                html_content = generate_html_report(results)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                log_info(f"HTML report saved to {output_path}")
                
        except Exception as e:
            log_error(f"Error saving results: {str(e)}")
    
    def print_summary(self, results):
        """Print a colored summary of findings"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}JSFlow AI - Analysis Summary")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        total_files = len(results)
        files_with_findings = 0
        total_endpoints = 0
        total_secrets = 0
        total_vulnerabilities = 0
        
        for result in results:
            if 'error' in result:
                continue
                
            parsing = result.get('parsing_results', {})
            ai_analysis = result.get('ai_analysis', {})
            
            endpoints = len(parsing.get('endpoints', []))
            secrets = len(parsing.get('secrets', []))
            vulnerabilities = len(ai_analysis.get('vulnerabilities', []))
            
            if endpoints > 0 or secrets > 0 or vulnerabilities > 0:
                files_with_findings += 1
                
            total_endpoints += endpoints
            total_secrets += secrets
            total_vulnerabilities += vulnerabilities
        
        print(f"{Fore.GREEN}📁 Files analyzed: {total_files}")
        print(f"{Fore.YELLOW}🔍 Files with findings: {files_with_findings}")
        print(f"{Fore.BLUE}🌐 API endpoints found: {total_endpoints}")
        print(f"{Fore.RED}🔑 Potential secrets: {total_secrets}")
        print(f"{Fore.MAGENTA}⚠️  Vulnerabilities identified: {total_vulnerabilities}{Style.RESET_ALL}")
        
        # Show top findings
        if files_with_findings > 0:
            print(f"\n{Fore.CYAN}🎯 Top Findings:{Style.RESET_ALL}")
            for result in results[:3]:  # Show top 3 results
                if 'error' in result:
                    continue
                    
                file_path = result['file_path']
                parsing = result.get('parsing_results', {})
                ai_analysis = result.get('ai_analysis', {})
                
                print(f"\n{Fore.WHITE}📄 {os.path.basename(file_path)}{Style.RESET_ALL}")
                
                if parsing.get('endpoints'):
                    print(f"  {Fore.BLUE}🌐 Endpoints: {len(parsing['endpoints'])}{Style.RESET_ALL}")
                    
                if parsing.get('secrets'):
                    print(f"  {Fore.RED}🔑 Secrets: {len(parsing['secrets'])}{Style.RESET_ALL}")
                    
                if ai_analysis.get('attack_vectors'):
                    print(f"  {Fore.MAGENTA}💡 AI Suggestions: {len(ai_analysis['attack_vectors'])}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="JSFlow AI - JavaScript Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --input test_samples/sample1.js
  python main.py --input /path/to/js/files --output results.json
  python main.py --input app.js --format html --output report.html
  python main.py --input src/ --batch --output analysis/
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input JavaScript file or directory to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='output/analysis_results.json',
        help='Output file path (default: output/analysis_results.json)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'html'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--batch', '-b',
        action='store_true',
        help='Batch process all JS files in directory'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Skip AI analysis (regex only)'
    )
    
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        default=True,
        help='Recursively analyze subdirectories (default: True)'
    )
    
    parser.add_argument(
        '--exclude',
        nargs='*',
        default=['node_modules', '.git', 'dist', 'build', 'coverage'],
        help='Directories to exclude from analysis'
    )
    
    parser.add_argument(
        '--severity-filter',
        choices=['critical', 'high', 'medium', 'low', 'all'],
        default='all',
        help='Filter results by minimum severity level'
    )
    
    parser.add_argument(
        '--only-secrets',
        action='store_true',
        help='Only scan for secrets and API keys'
    )
    
    parser.add_argument(
        '--risk-threshold',
        choices=['critical', 'high', 'medium', 'low'],
        default='low',
        help='Minimum risk level to report'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    # Initialize JSFlow AI
    jsflow = JSFlowAI()
    
    # Disable AI if requested
    if args.no_ai:
        jsflow.ai_analyzer.enabled = False
        log_info("AI analysis disabled - using regex patterns only")
    
    # Check input path
    input_path = Path(args.input)
    if not input_path.exists():
        log_error(f"Input path does not exist: {args.input}")
        sys.exit(1)
    
    # Analyze files
    results = []
    
    if input_path.is_file():
        # Single file analysis
        result = jsflow.analyze_file(input_path)
        results = [result]
        
    elif input_path.is_dir():
        # Directory analysis
        if args.batch:
            results = jsflow.analyze_directory(input_path)
        else:
            log_error("Directory provided but --batch flag not set")
            sys.exit(1)
    
    if not results:
        log_error("No files were analyzed")
        sys.exit(1)
    
    # Save results
    jsflow.save_results(results, args.format, args.output)
    
    # Print summary
    jsflow.print_summary(results)
    
    print(f"\n{Fore.GREEN}✅ Analysis complete! Results saved to: {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
