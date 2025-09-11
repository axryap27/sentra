import * as vscode from 'vscode';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface SecurityIssue {
    line: number;
    issue: string;
    severity: 'High' | 'Medium' | 'Low';
}

export interface SecurityReport {
    fileName: string;
    issues: SecurityIssue[];
}

export class SecurityAnalyzer {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private context: vscode.ExtensionContext;
    private pythonAnalyzerPath: string;
    private lastWorkspaceReport: SecurityReport[] = [];

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securityAnalyzer');
        
        // Path to the Python analyzer script
        this.pythonAnalyzerPath = path.join(context.extensionPath, 'backend', 'analyzer.py');
        
        context.subscriptions.push(this.diagnosticCollection);
    }

    async scanFile(uri: vscode.Uri): Promise<void> {
        if (path.extname(uri.fsPath) !== '.py') {
            return;
        }

        try {
            const document = await vscode.workspace.openTextDocument(uri);
            const issues = await this.analyzePythonFile(document.getText());
            this.updateDiagnostics(uri, issues);
        } catch (error) {
            console.error('Error scanning file:', error);
            vscode.window.showErrorMessage(`Failed to scan file: ${error}`);
        }
    }

    async scanWorkspace(): Promise<SecurityReport[] | null> {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        if (!config.get('enabled')) {
            return null;
        }

        // Find all Python files in workspace
        const pythonFiles = await vscode.workspace.findFiles('**/*.py', '**/node_modules/**');
        
        if (pythonFiles.length === 0) {
            vscode.window.showInformationMessage('No Python files found in workspace');
            return null;
        }

        const reports: SecurityReport[] = [];

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Scanning workspace for security vulnerabilities...',
            cancellable: true
        }, async (progress, token) => {
            const total = pythonFiles.length;
            let processed = 0;

            for (const file of pythonFiles) {
                if (token.isCancellationRequested) {
                    break;
                }

                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const issues = await this.analyzePythonFile(document.getText());
                    
                    this.updateDiagnostics(file, issues);
                    
                    if (issues.length > 0) {
                        reports.push({
                            fileName: vscode.workspace.asRelativePath(file),
                            issues: issues
                        });
                    }
                } catch (error) {
                    console.error(`Error scanning ${file.fsPath}:`, error);
                }

                processed++;
                
                progress.report({
                    increment: (100 / total),
                    message: `${processed}/${total} files scanned`
                });
            }

            if (!token.isCancellationRequested) {
                vscode.window.showInformationMessage(`Workspace scan completed. Scanned ${processed} Python files.`);
            }
        });

        this.lastWorkspaceReport = reports;
        return reports;
    }

    private async analyzePythonFile(code: string): Promise<SecurityIssue[]> {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        
        // Use Go binary instead of Python
        const goBinaryPath = path.join(this.context.extensionPath, 'analyzer-go', 'sentra-analyzer');
        const goBinaryPathWindows = goBinaryPath + '.exe';
        
        // Check if Go binary exists, fallback to building it
        const fs = require('fs');
        let binaryPath = goBinaryPath;
        
        if (process.platform === 'win32') {
            binaryPath = goBinaryPathWindows;
        }
        
        if (!fs.existsSync(binaryPath)) {
            // Build the Go binary
            try {
                await execAsync('go build -o sentra-analyzer .', {
                    cwd: path.join(this.context.extensionPath, 'analyzer-go'),
                    timeout: 60000 // 1 minute timeout for building
                });
            } catch (buildError) {
                console.error('Failed to build Go analyzer:', buildError);
                throw new Error('Failed to build security analyzer');
            }
        }

        try {
            // Write code to temporary file
            const os = require('os');
            const tempFile = path.join(os.tmpdir(), `sentra_analyzer_${Date.now()}.py`);
            
            await fs.promises.writeFile(tempFile, code, 'utf8');

            const { stdout, stderr } = await execAsync(`"${binaryPath}" --file "${tempFile}" --format json`, {
                cwd: this.context.extensionPath,
                timeout: 30000 // 30 second timeout
            });

            // Clean up temp file
            try {
                await fs.promises.unlink(tempFile);
            } catch (cleanupError) {
                console.warn('Failed to clean up temp file:', cleanupError);
            }

            if (stderr) {
                console.warn('Go analyzer stderr:', stderr);
            }

            const issues: SecurityIssue[] = JSON.parse(stdout.trim() || '[]');
            return this.filterIssuesBySeverity(issues);
        } catch (error) {
            console.error('Go analyzer error:', error);
            throw new Error(`AI analysis failed: ${error}`);
        }
    }

    private filterIssuesBySeverity(issues: SecurityIssue[]): SecurityIssue[] {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        const minSeverity = config.get('severityLevel', 'Medium');
        
        const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        const minLevel = severityOrder[minSeverity as keyof typeof severityOrder] || 2;

        return issues.filter(issue => {
            const issueLevel = severityOrder[issue.severity] || 0;
            return issueLevel >= minLevel;
        });
    }

    private updateDiagnostics(uri: vscode.Uri, issues: SecurityIssue[]): void {
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                Math.max(0, issue.line - 1), // VS Code lines are 0-based
                0,
                Math.max(0, issue.line - 1),
                Number.MAX_VALUE
            );

            const severity = this.getSeverityLevel(issue.severity);
            const diagnostic = new vscode.Diagnostic(range, issue.issue, severity);
            
            diagnostic.source = 'Sentra';
            diagnostic.code = issue.severity.toLowerCase();
            
            return diagnostic;
        });

        this.diagnosticCollection.set(uri, diagnostics);
    }

    private getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'High':
                return vscode.DiagnosticSeverity.Error;
            case 'Medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'Low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    getLastWorkspaceReport(): SecurityReport[] | null {
        return this.lastWorkspaceReport.length > 0 ? this.lastWorkspaceReport : null;
    }

    clearAllDiagnostics(): void {
        this.diagnosticCollection.clear();
        vscode.window.showInformationMessage('Security diagnostics cleared');
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}