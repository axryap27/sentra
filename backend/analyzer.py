import ast

SEVERITY = {
    "eval": "High",
    "hardcoded_api_key": "High",
    "md5": "Medium",
    "sha1": "Medium",
    "sql_injection": "High",
}

def detect_vulnerabilities(code: str) -> list[dict]:
    issues = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [{"line": 0, "issue": f"Syntax error: {e}", "severity": "High"}]

    for node in ast.walk(tree):
        # Detect eval
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'eval':
            issues.append({
                "line": node.lineno,
                "issue": "Use of eval() detected. This can lead to code injection.",
                "severity": SEVERITY["eval"]
            })

        # Hardcoded API keys
        if isinstance(node, ast.Assign):
            for val in ast.walk(node):
                if isinstance(val, ast.Str) and "sk-" in val.s:
                    issues.append({
                        "line": val.lineno,
                        "issue": "Possible hardcoded API key detected.",
                        "severity": SEVERITY["hardcoded_api_key"]
                    })

        # Insecure hash functions
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ["md5", "sha1"]:
                issues.append({
                    "line": node.lineno,
                    "issue": f"Insecure hash function '{node.func.attr}' used.",
                    "severity": SEVERITY[node.func.attr]
                })

        # SQL Injection via string formatting
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "execute":
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                        issues.append({
                            "line": node.lineno,
                            "issue": "SQL injection risk: string formatting in SQL query.",
                            "severity": SEVERITY["sql_injection"]
                        })

    return issues
