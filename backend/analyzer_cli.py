#!/usr/bin/env python3
"""
Command-line interface for the security analyzer.
This script can be called from the VS Code extension.
"""
import sys
import json
import argparse
from analyzer import detect_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Analyze Python code for security vulnerabilities')
    parser.add_argument('--file', help='File to analyze')
    parser.add_argument('--stdin', action='store_true', help='Read code from stdin')
    parser.add_argument('--format', choices=['json', 'text'], default='json', help='Output format')
    
    args = parser.parse_args()
    
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.stdin:
        code = sys.stdin.read()
    else:
        print("Error: Either --file or --stdin must be specified", file=sys.stderr)
        sys.exit(1)
    
    try:
        issues = detect_vulnerabilities(code)
        
        if args.format == 'json':
            print(json.dumps(issues, indent=2))
        else:
            if not issues:
                print("No security vulnerabilities found.")
            else:
                for i, issue in enumerate(issues, 1):
                    print(f"{i}. [Line {issue['line']}] ({issue['severity']}) {issue['issue']}")
                    
    except Exception as e:
        print(f"Analysis error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()