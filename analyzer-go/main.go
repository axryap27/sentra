package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type SecurityIssue struct {
	Line     int    `json:"line"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
}

type Language string

const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageJava       Language = "java"
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
	LanguageGo         Language = "go"
	LanguagePHP        Language = "php"
	LanguageCSharp     Language = "csharp"
	LanguageRust       Language = "rust"
	LanguageUnknown    Language = "unknown"
)

type Analyzer struct {
	fileSet  *token.FileSet
	issues   []SecurityIssue
	language Language
}

func NewAnalyzer(language Language) *Analyzer {
	return &Analyzer{
		fileSet:  token.NewFileSet(),
		issues:   make([]SecurityIssue, 0),
		language: language,
	}
}

func (a *Analyzer) addIssue(pos token.Pos, issue, severity string) {
	position := a.fileSet.Position(pos)
	a.issues = append(a.issues, SecurityIssue{
		Line:     position.Line,
		Issue:    issue,
		Severity: severity,
	})
}

func (a *Analyzer) analyzeFile(content string) error {
	// Use AI-powered analysis with language-specific patterns
	aiAnalyzer := NewAIAnalyzer(a.language)
	
	aiIssues, err := aiAnalyzer.AnalyzeWithAI(content)
	if err != nil {
		return fmt.Errorf("AI analysis failed: %v", err)
	}
	
	a.issues = aiIssues
	return nil
}

func (a *Analyzer) getIssues() []SecurityIssue {
	return a.issues
}

func main() {
	var filePath = flag.String("file", "", "File to analyze")
	var format = flag.String("format", "json", "Output format (json or text)")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintf(os.Stderr, "Error: --file parameter is required\n")
		os.Exit(1)
	}

	content, err := os.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Detect language from file path
	language := detectLanguage(*filePath)
	
	analyzer := NewAnalyzer(language)
	err = analyzer.analyzeFile(string(content))
	if err != nil {
		log.Fatalf("Analysis error: %v", err)
	}

	issues := analyzer.getIssues()

	if *format == "json" {
		jsonOutput, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	} else {
		if len(issues) == 0 {
			fmt.Println("No security vulnerabilities found.")
		} else {
			for i, issue := range issues {
				fmt.Printf("%d. [Line %d] (%s) %s\n", i+1, issue.Line, issue.Severity, issue.Issue)
			}
		}
	}
}

// detectLanguage determines the programming language from file extension
func detectLanguage(filePath string) Language {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".py":
		return LanguagePython
	case ".js", ".jsx":
		return LanguageJavaScript
	case ".ts", ".tsx":
		return LanguageTypeScript
	case ".java":
		return LanguageJava
	case ".c":
		return LanguageC
	case ".cpp", ".cc", ".cxx", ".hpp", ".h":
		return LanguageCPP
	case ".go":
		return LanguageGo
	case ".php":
		return LanguagePHP
	case ".cs":
		return LanguageCSharp
	case ".rs":
		return LanguageRust
	default:
		return LanguageUnknown
	}
}