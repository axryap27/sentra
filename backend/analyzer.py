import ast

def detect_vulnerabilities(code: str) -> list[str]:
    issues = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Syntax error: {e}"]

    for node in ast.walk(tree):
        # Detect use of eval()
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'eval':
            issues.append("Use of eval() detected. This can lead to code injection vulnerabilities.")

        # Detect hardcoded strings that look like API keys
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Str) and 'sk-' in t.s for t in ast.walk(node)):
                issues.append("Possible hardcoded API key detected.")

        # Detect use of md5 or sha1 from hashlib
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ['md5', 'sha1']:
                issues.append(f"Insecure hash function '{node.func.attr}' used. Use SHA-256 or bcrypt instead.")

        # Detect SQL query string formatting
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                        issues.append("Possible SQL injection via string formatting in SQL query.")

    return issues
