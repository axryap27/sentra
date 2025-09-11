# Sentra

Real-time security vulnerability scanner for VS Code. Currently focuses on Python code but extensible to other languages.

## What it does

Sentra finds security problems in your Python code as you write it. It catches things like:

- Code injection (eval, exec)
- Command injection (subprocess with shell=True)
- Hardcoded secrets and API keys
- Weak hash functions (MD5, SHA1)
- SQL injection vulnerabilities
- Unsafe deserialization (pickle, yaml)
- XSS and path traversal issues

## How to use

### Install

1. Install the extension from VS Code marketplace
2. Open a Python file
3. The scanner runs automatically

### Commands

Open Command Palette (Ctrl+Shift+P) and run:

- `Scan File for Vulnerabilities` - Scan current file
- `Scan Workspace for Vulnerabilities` - Scan all Python files
- `Clear Security Diagnostics` - Remove all warnings
- `Show Security Report` - View detailed report

### Settings

Go to VS Code Settings and search for "Sentra":

- Enable/disable the scanner
- Turn auto-scan on save on/off
- Set minimum severity level (High/Medium/Low)
- Exclude files or folders from scanning

### What you see

Security issues show up as:
- Red underlines for high severity issues
- Yellow underlines for medium severity
- Blue underlines for low severity
- Problems panel shows all issues
- Status bar shows total issue count

## Requirements

- VS Code 1.74.0 or newer
- Go installed on your system (for building the analyzer)

## How it works

The extension uses a Go backend with AI-powered pattern matching to analyze your Python code. It looks at the code structure and content to find potential security vulnerabilities with confidence scoring.

## License

MIT