# JSFlow AI - JavaScript Security Analysis Tool

## Overview

JSFlow AI is a command-line security analysis tool designed to identify vulnerabilities in JavaScript code. The application combines regex-based pattern matching with OpenAI's GPT-4o model to provide comprehensive security analysis, including endpoint discovery, secret detection, and vulnerability assessment. The tool generates both console output and HTML reports for security analysis results.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

JSFlow AI follows a modular architecture with clear separation of concerns:

- **CLI Interface**: Main entry point that handles command-line arguments and orchestrates the analysis workflow
- **JavaScript Parser**: Regex-based pattern matching engine for static code analysis
- **AI Analyzer**: OpenAI integration for intelligent vulnerability detection and recommendations
- **Utilities**: Shared functionality for logging, reporting, and code beautification

The architecture prioritizes modularity and extensibility, allowing for easy addition of new analysis techniques or output formats.

## Key Components

### 1. Main CLI Interface (`main.py`)
- **Purpose**: Primary entry point and workflow orchestration
- **Features**: Command-line argument parsing, file discovery, progress tracking with tqdm
- **Dependencies**: Integrates JSParser and AIAnalyzer modules

### 2. JavaScript Parser (`js_parser.py`)
- **Purpose**: Static analysis using regex patterns
- **Analysis Targets**:
  - API endpoints and URL patterns
  - Hardcoded secrets and API keys
  - Suspicious function calls (eval, setTimeout with strings)
  - Framework-specific patterns (fetch, axios, XMLHttpRequest)
- **Pattern Categories**: Endpoints, secrets, suspicious functions with comprehensive regex coverage

### 3. AI Analyzer (`ai_analyzer.py`)
- **Purpose**: Intelligent vulnerability analysis using OpenAI GPT-4o
- **Features**: 
  - Contextual security analysis
  - Vulnerability scoring
  - Attack vector identification
  - Security recommendations
- **Fallback**: Graceful degradation when API key is unavailable

### 4. Utilities (`utils.py`)
- **Purpose**: Shared functionality across modules
- **Features**:
  - Logging with colored console output
  - JavaScript code beautification using jsbeautifier
  - HTML report generation
  - File system utilities

### 5. Report Generation
- **Format**: Bootstrap-based HTML reports with syntax highlighting
- **Features**: Interactive dashboard with vulnerability categorization and detailed analysis results
- **Template**: Professional styling with responsive design

## Data Flow

1. **Input Processing**: CLI accepts file paths or directories for JavaScript analysis
2. **Code Preparation**: Files are read and beautified for optimal analysis
3. **Static Analysis**: JSParser extracts patterns using regex matching
4. **AI Enhancement**: AIAnalyzer provides contextual vulnerability assessment
5. **Result Aggregation**: Parsing and AI results are combined into comprehensive analysis
6. **Output Generation**: Results are displayed in console and optionally exported to HTML

## External Dependencies

### Core Libraries
- **OpenAI**: GPT-4o integration for intelligent analysis
- **jsbeautifier**: JavaScript code formatting and beautification
- **colorama**: Cross-platform colored terminal output
- **tqdm**: Progress bar functionality

### Frontend (HTML Reports)
- **Bootstrap 5.1.3**: UI framework for responsive report design
- **Font Awesome 6.0.0**: Icon library for visual enhancement
- **Prism.js**: Syntax highlighting for code display

### Python Standard Library
- **argparse**: Command-line interface
- **pathlib**: File system operations
- **json**: Data serialization
- **re**: Regular expression processing
- **logging**: Application logging

## Deployment Strategy

### Development Environment
- **Structure**: Self-contained Python application with minimal external dependencies
- **Configuration**: Environment variable-based configuration (OPENAI_API_KEY)
- **Logging**: File-based logging with console output for debugging

### Distribution Considerations
- **Packaging**: Standard Python package structure suitable for pip installation
- **Dependencies**: All dependencies specified for easy environment setup
- **Cross-platform**: Compatible with Windows, macOS, and Linux through colorama

### Security Considerations
- **API Key Management**: Secure handling of OpenAI API keys through environment variables
- **Graceful Degradation**: Tool remains functional without AI features when API key is unavailable
- **Data Privacy**: Local processing with optional external API calls for enhanced analysis

The application is designed as a portable CLI tool that can be easily integrated into CI/CD pipelines or used for ad-hoc security analysis of JavaScript codebases.