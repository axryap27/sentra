def analyze_code_with_ai(code: str) -> str:
    # Placeholder for your actual logic
    return "Analysis not implemented yet"

from backend.analyzer import detect_vulnerabilities

def analyze_code_with_ai(code: str) -> str:
    issues = detect_vulnerabilities(code)

    if not issues:
        return "No obvious vulnerabilities found."
    
    report_lines = []
    for i, issue in enumerate(issues, 1):
        report_lines.append(
            f"{i}. [Line {issue['line']}] ({issue['severity']}) {issue['issue']}"
        )

    return "\n".join(report_lines)