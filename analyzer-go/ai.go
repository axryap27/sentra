package main

import (
	"fmt"
	"strings"
)

// AIAnalyzer provides AI-powered security analysis
type AIAnalyzer struct {
	// For now, we'll use rule-based detection with AI-like scoring
	// Later we can integrate with actual AI agents (OpenAI, Anthropic, local models)
	language Language
}

type VulnerabilityPattern struct {
	Pattern     string
	Severity    string
	Description string
	AIScore     float64 // Confidence score (0.0 - 1.0)
}

var pythonVulnerabilityPatterns = []VulnerabilityPattern{
	{
		Pattern:     "eval(",
		Severity:    "High",
		Description: "Code injection vulnerability: eval() executes arbitrary code",
		AIScore:     0.95,
	},
	{
		Pattern:     "exec(",
		Severity:    "High", 
		Description: "Code injection vulnerability: exec() executes arbitrary code",
		AIScore:     0.92,
	},
	{
		Pattern:     "shell=True",
		Severity:    "High",
		Description: "Command injection vulnerability: subprocess with shell=True",
		AIScore:     0.88,
	},
	{
		Pattern:     "pickle.load",
		Severity:    "High",
		Description: "Unsafe deserialization: pickle can execute arbitrary code",
		AIScore:     0.90,
	},
	{
		Pattern:     "yaml.load(",
		Severity:    "High",
		Description: "Unsafe deserialization: yaml.load() without safe loader",
		AIScore:     0.85,
	},
	{
		Pattern:     ".md5(",
		Severity:    "Medium",
		Description: "Cryptographic weakness: MD5 is broken hash function",
		AIScore:     0.75,
	},
	{
		Pattern:     ".sha1(",
		Severity:    "Medium",
		Description: "Cryptographic weakness: SHA1 is vulnerable hash function",
		AIScore:     0.75,
	},
	{
		Pattern:     "random.random()",
		Severity:    "Medium",
		Description: "Weak randomness: not cryptographically secure",
		AIScore:     0.65,
	},
	{
		Pattern:     "request.args.get",
		Severity:    "Medium",
		Description: "Potential XSS: unsanitized user input",
		AIScore:     0.60,
	},
	{
		Pattern:     "os.system(",
		Severity:    "High",
		Description: "Command injection: os.system() executes shell commands",
		AIScore:     0.93,
	},
}

// JavaScript/TypeScript vulnerability patterns
var javascriptVulnerabilityPatterns = []VulnerabilityPattern{
	{
		Pattern:     "eval(",
		Severity:    "High",
		Description: "Code injection vulnerability: eval() executes arbitrary JavaScript code",
		AIScore:     0.95,
	},
	{
		Pattern:     "Function(",
		Severity:    "High",
		Description: "Code injection vulnerability: Function() constructor executes arbitrary code",
		AIScore:     0.90,
	},
	{
		Pattern:     "innerHTML",
		Severity:    "High",
		Description: "XSS vulnerability: innerHTML can execute malicious scripts",
		AIScore:     0.85,
	},
	{
		Pattern:     "dangerouslySetInnerHTML",
		Severity:    "High",
		Description: "XSS vulnerability: dangerouslySetInnerHTML bypasses React's XSS protection",
		AIScore:     0.90,
	},
	{
		Pattern:     "document.write(",
		Severity:    "High",
		Description: "XSS vulnerability: document.write() can inject malicious content",
		AIScore:     0.80,
	},
	{
		Pattern:     "setTimeout(",
		Severity:    "Medium",
		Description: "Code injection risk: setTimeout with string parameter executes code",
		AIScore:     0.70,
	},
	{
		Pattern:     "setInterval(",
		Severity:    "Medium",
		Description: "Code injection risk: setInterval with string parameter executes code",
		AIScore:     0.70,
	},
	{
		Pattern:     "localStorage.setItem",
		Severity:    "Low",
		Description: "Data exposure risk: sensitive data stored in localStorage",
		AIScore:     0.50,
	},
	{
		Pattern:     "Math.random()",
		Severity:    "Medium",
		Description: "Weak randomness: Math.random() is not cryptographically secure",
		AIScore:     0.65,
	},
	{
		Pattern:     "exec(",
		Severity:    "High",
		Description: "Command injection vulnerability: child_process.exec() executes shell commands",
		AIScore:     0.92,
	},
}

// Java vulnerability patterns
var javaVulnerabilityPatterns = []VulnerabilityPattern{
	{
		Pattern:     "Runtime.getRuntime().exec(",
		Severity:    "High",
		Description: "Command injection vulnerability: Runtime.exec() executes system commands",
		AIScore:     0.95,
	},
	{
		Pattern:     "ProcessBuilder(",
		Severity:    "High", 
		Description: "Command injection risk: ProcessBuilder can execute system commands",
		AIScore:     0.85,
	},
	{
		Pattern:     "ObjectInputStream",
		Severity:    "High",
		Description: "Unsafe deserialization: ObjectInputStream can execute arbitrary code",
		AIScore:     0.90,
	},
	{
		Pattern:     "Math.random()",
		Severity:    "Medium",
		Description: "Weak randomness: Math.random() is not cryptographically secure",
		AIScore:     0.65,
	},
	{
		Pattern:     "MessageDigest.getInstance(\"MD5\")",
		Severity:    "Medium",
		Description: "Cryptographic weakness: MD5 is a broken hash function",
		AIScore:     0.75,
	},
	{
		Pattern:     "MessageDigest.getInstance(\"SHA1\")",
		Severity:    "Medium",
		Description: "Cryptographic weakness: SHA1 is vulnerable hash function",
		AIScore:     0.75,
	},
	{
		Pattern:     "Class.forName(",
		Severity:    "Medium",
		Description: "Reflection risk: Class.forName() can load arbitrary classes",
		AIScore:     0.70,
	},
	{
		Pattern:     "executeQuery(",
		Severity:    "High",
		Description: "SQL injection risk: dynamic query construction detected",
		AIScore:     0.80,
	},
}

// C/C++ vulnerability patterns
var cVulnerabilityPatterns = []VulnerabilityPattern{
	{
		Pattern:     "strcpy(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: strcpy() doesn't check buffer bounds",
		AIScore:     0.95,
	},
	{
		Pattern:     "strcat(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: strcat() doesn't check buffer bounds",
		AIScore:     0.90,
	},
	{
		Pattern:     "sprintf(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: sprintf() doesn't check buffer bounds",
		AIScore:     0.88,
	},
	{
		Pattern:     "gets(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: gets() has no bounds checking",
		AIScore:     0.98,
	},
	{
		Pattern:     "scanf(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: scanf() can overflow buffers",
		AIScore:     0.85,
	},
	{
		Pattern:     "printf(",
		Severity:    "Medium",
		Description: "Format string vulnerability: printf() with user-controlled format string",
		AIScore:     0.75,
	},
	{
		Pattern:     "system(",
		Severity:    "High",
		Description: "Command injection vulnerability: system() executes shell commands",
		AIScore:     0.93,
	},
	{
		Pattern:     "malloc(",
		Severity:    "Medium",
		Description: "Memory management risk: malloc() without proper free() can cause leaks",
		AIScore:     0.60,
	},
	{
		Pattern:     "free(",
		Severity:    "Medium",
		Description: "Memory management risk: free() without proper null check can cause crashes",
		AIScore:     0.65,
	},
	{
		Pattern:     "memcpy(",
		Severity:    "High",
		Description: "Buffer overflow vulnerability: memcpy() doesn't validate buffer sizes",
		AIScore:     0.80,
	},
	{
		Pattern:     "rand(",
		Severity:    "Medium",
		Description: "Weak randomness: rand() is not cryptographically secure",
		AIScore:     0.65,
	},
}

func NewAIAnalyzer(language Language) *AIAnalyzer {
	return &AIAnalyzer{
		language: language,
	}
}

// getVulnerabilityPatterns returns language-specific vulnerability patterns
func (ai *AIAnalyzer) getVulnerabilityPatterns() []VulnerabilityPattern {
	switch ai.language {
	case LanguagePython:
		return pythonVulnerabilityPatterns
	case LanguageJavaScript, LanguageTypeScript:
		return javascriptVulnerabilityPatterns
	case LanguageJava:
		return javaVulnerabilityPatterns
	case LanguageC, LanguageCPP:
		return cVulnerabilityPatterns
	default:
		// For unsupported languages, return Python patterns as fallback
		// In the future, this could return general patterns or use AI agent
		return pythonVulnerabilityPatterns
	}
}

// AnalyzeWithAI performs AI-powered security analysis
func (ai *AIAnalyzer) AnalyzeWithAI(content string) ([]SecurityIssue, error) {
	var issues []SecurityIssue
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Check against language-specific AI-powered vulnerability patterns
		patterns := ai.getVulnerabilityPatterns()
		for _, pattern := range patterns {
			if strings.Contains(trimmedLine, pattern.Pattern) {
				// Skip if it's in a comment
				if strings.HasPrefix(trimmedLine, "#") {
					continue
				}
				
				issue := SecurityIssue{
					Line:     lineNum + 1,
					Issue:    pattern.Description,
					Severity: pattern.Severity,
				}
				
				// Add AI confidence score as metadata
				if pattern.AIScore > 0.8 {
					issue.Issue += " (High confidence)"
				} else if pattern.AIScore > 0.6 {
					issue.Issue += " (Medium confidence)"
				} else {
					issue.Issue += " (Low confidence)"
				}
				
				issues = append(issues, issue)
			}
		}
		
		// Advanced pattern detection using AI-like heuristics
		issues = append(issues, ai.detectAdvancedPatterns(lineNum+1, trimmedLine)...)
	}

	return ai.deduplicateIssues(issues), nil
}

// detectAdvancedPatterns uses more sophisticated AI-like analysis
func (ai *AIAnalyzer) detectAdvancedPatterns(lineNum int, line string) []SecurityIssue {
	var issues []SecurityIssue
	
	// SQL Injection detection with context awareness
	if strings.Contains(line, "execute(") || strings.Contains(line, "query(") {
		if strings.Contains(line, "+") || strings.Contains(line, "%") || strings.Contains(line, "format(") {
			issues = append(issues, SecurityIssue{
				Line:     lineNum,
				Issue:    "SQL injection vulnerability: dynamic query construction detected (AI Analysis)",
				Severity: "High",
			})
		}
	}
	
	// XSS detection
	if strings.Contains(line, "render_template") || strings.Contains(line, "HttpResponse") {
		if strings.Contains(line, "request.") && !strings.Contains(line, "escape(") {
			issues = append(issues, SecurityIssue{
				Line:     lineNum,
				Issue:    "XSS vulnerability: user input rendered without escaping (AI Analysis)",
				Severity: "Medium",
			})
		}
	}
	
	// Path traversal detection
	if strings.Contains(line, "open(") && strings.Contains(line, "request.") {
		if !strings.Contains(line, "safe_join") && !strings.Contains(line, "secure_filename") {
			issues = append(issues, SecurityIssue{
				Line:     lineNum,
				Issue:    "Path traversal vulnerability: user-controlled file access (AI Analysis)",
				Severity: "High",
			})
		}
	}
	
	// Hardcoded secrets detection with AI patterns
	if ai.containsSecretPattern(line) {
		issues = append(issues, SecurityIssue{
			Line:     lineNum,
			Issue:    "Hardcoded secret detected: potential credential leak (AI Analysis)",
			Severity: "High",
		})
	}
	
	return issues
}

// containsSecretPattern uses AI-like heuristics to detect secrets
func (ai *AIAnalyzer) containsSecretPattern(line string) bool {
	secretPatterns := []string{
		"password", "passwd", "pwd", "secret", "key", "token", "api_key",
		"access_key", "secret_key", "private_key", "auth", "credential",
	}
	
	assignmentOperators := []string{"=", ":", "->"}
	
	for _, pattern := range secretPatterns {
		if strings.Contains(strings.ToLower(line), pattern) {
			for _, op := range assignmentOperators {
				if strings.Contains(line, op) {
					// Check if it looks like a hardcoded value
					parts := strings.Split(line, op)
					if len(parts) > 1 {
						value := strings.TrimSpace(parts[1])
						if len(value) > 8 && !strings.Contains(value, "input(") && 
						   !strings.Contains(value, "os.environ") {
							return true
						}
					}
				}
			}
		}
	}
	
	// Check for common secret formats
	secretFormats := []string{"sk-", "pk-", "AIza", "AKIA", "ghp_", "gho_"}
	for _, format := range secretFormats {
		if strings.Contains(line, format) {
			return true
		}
	}
	
	return false
}

// deduplicateIssues removes duplicate issues on the same line
func (ai *AIAnalyzer) deduplicateIssues(issues []SecurityIssue) []SecurityIssue {
	seen := make(map[string]bool)
	var result []SecurityIssue
	
	for _, issue := range issues {
		key := fmt.Sprintf("%d:%s", issue.Line, issue.Issue)
		if !seen[key] {
			seen[key] = true
			result = append(result, issue)
		}
	}
	
	return result
}

// GetAnalysisReport generates a detailed AI analysis report
func (ai *AIAnalyzer) GetAnalysisReport(issues []SecurityIssue) string {
	if len(issues) == 0 {
		return "AI Analysis: No security vulnerabilities detected. Code appears secure."
	}
	
	report := fmt.Sprintf("AI Security Analysis Report\n")
	report += fmt.Sprintf("============================\n")
	report += fmt.Sprintf("Total Issues Found: %d\n\n", len(issues))
	
	// Group by severity
	severityCount := make(map[string]int)
	for _, issue := range issues {
		severityCount[issue.Severity]++
	}
	
	for severity, count := range severityCount {
		report += fmt.Sprintf("%s Severity: %d issues\n", severity, count)
	}
	
	report += "\nDetailed Findings:\n"
	for i, issue := range issues {
		report += fmt.Sprintf("%d. Line %d [%s]: %s\n", 
			i+1, issue.Line, issue.Severity, issue.Issue)
	}
	
	return report
}