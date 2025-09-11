package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"log"
	"os"
)

type SecurityIssue struct {
	Line     int    `json:"line"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
}

type Analyzer struct {
	fileSet *token.FileSet
	issues  []SecurityIssue
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		fileSet: token.NewFileSet(),
		issues:  make([]SecurityIssue, 0),
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

func (a *Analyzer) analyzePythonFile(content string) error {
	// Use AI-powered analysis
	aiAnalyzer := NewAIAnalyzer()
	
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

	analyzer := NewAnalyzer()
	err = analyzer.analyzePythonFile(string(content))
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