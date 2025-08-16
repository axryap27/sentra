def analyze_code_with_ai(code: str) -> str:
    # Placeholder for your actual logic
    return "Analysis not implemented yet"

from backend.analyzer import detect_vulnerabilities

def analyze_code_with_ai(code: str) -> str:
    issues = detect_vulnerabilities(code)

    if not issues:
        return "No obvious vulnerabilities found."

    return "\n".join(f"{i + 1}. {issue}" for i, issue in enumerate(issues))
