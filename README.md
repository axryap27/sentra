# Sentra

Real-time security vulnerability scanner for VS Code.

## What it does

Sentra finds security problems in your code as you write it. It supports Python, JavaScript, TypeScript, Java, C, C++, Go, PHP, C#, and Rust. It catches things like:

- Code injection (eval, exec)
- Command injection (subprocess with shell=True, system())
- Hardcoded secrets and API keys
- Weak hash functions (MD5, SHA1)
- SQL injection vulnerabilities
- Unsafe deserialization (pickle, yaml, ObjectInputStream)
- XSS and path traversal issues
- Buffer overflows (strcpy, gets, memcpy)
- Memory leaks (malloc without free)
- Weak randomness (Math.random, rand)

## How to use

### Install

1. Install the extension from VS Code marketplace
2. Open a file
3. The scanner runs automatically

### Commands

Open Command Palette (Ctrl+Shift+P) and run:

- `Scan File for Vulnerabilities` - Scan current file
- `Scan Workspace for Vulnerabilities` - Scan all supported files in the workspace
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

## Supported Languages

| Language | Extensions |
|----------|------------|
| Python | `.py` |
| JavaScript | `.js`, `.jsx` |
| TypeScript | `.ts`, `.tsx` |
| Java | `.java` |
| C | `.c`, `.h` |
| C++ | `.cpp`, `.cc`, `.cxx`, `.hpp` |
| Go | `.go` |
| PHP | `.php` |
| C# | `.cs` |
| Rust | `.rs` |

## Requirements

- VS Code 1.74.0 or newer
- Go installed on your system (for building the analyzer)

## How it works

The extension uses a Go backend that parses your code into an Abstract Syntax Tree using tree-sitter, then runs a trained Random Forest classifier to detect vulnerabilities. Analysis is done entirely locally — no code is sent to any server.

## License

MIT