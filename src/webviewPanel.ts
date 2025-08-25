import * as vscode from 'vscode';
import * as path from 'path';

export interface SecurityReport {
    fileName: string;
    issues: Array<{
        line: number;
        issue: string;
        severity: 'High' | 'Medium' | 'Low';
    }>;
}

export class SecurityReportPanel {
    private panel: vscode.WebviewPanel | undefined;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    public showReport(reports: SecurityReport[]): void {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.Two);
        } else {
            this.panel = vscode.window.createWebviewPanel(
                'securityReport',
                'Security Analysis Report',
                vscode.ViewColumn.Two,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true
                }
            );

            this.panel.onDidDispose(() => {
                this.panel = undefined;
            });
        }

        this.panel.webview.html = this.getWebviewContent(reports);
    }

    private getWebviewContent(reports: SecurityReport[]): string {
        const totalIssues = reports.reduce((sum, report) => sum + report.issues.length, 0);
        const highSeverityCount = reports.reduce((sum, report) => 
            sum + report.issues.filter(issue => issue.severity === 'High').length, 0);
        const mediumSeverityCount = reports.reduce((sum, report) => 
            sum + report.issues.filter(issue => issue.severity === 'Medium').length, 0);
        const lowSeverityCount = reports.reduce((sum, report) => 
            sum + report.issues.filter(issue => issue.severity === 'Low').length, 0);

        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
        }
        .header {
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 20px;
            margin-bottom: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .metric {
            padding: 15px;
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            text-align: center;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .high { color: #f85149; }
        .medium { color: #f0ad4e; }
        .low { color: #5bc0de; }
        .file-report {
            margin-bottom: 30px;
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
        }
        .file-header {
            background-color: var(--vscode-editor-lineHighlightBackground);
            padding: 10px 15px;
            font-weight: bold;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .issue {
            padding: 10px 15px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .issue:last-child {
            border-bottom: none;
        }
        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        .line-number {
            font-family: monospace;
            background-color: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.85em;
        }
        .severity-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-high { background-color: #f85149; color: white; }
        .severity-medium { background-color: #f0ad4e; color: white; }
        .severity-low { background-color: #5bc0de; color: white; }
        .no-issues {
            text-align: center;
            padding: 40px;
            color: var(--vscode-descriptionForeground);
        }
        .shield-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Analysis Report</h1>
        <p>Analysis completed for ${reports.length} file${reports.length !== 1 ? 's' : ''}</p>
    </div>

    <div class="summary">
        <div class="metric">
            <div class="metric-value">${totalIssues}</div>
            <div>Total Issues</div>
        </div>
        <div class="metric">
            <div class="metric-value high">${highSeverityCount}</div>
            <div>High Severity</div>
        </div>
        <div class="metric">
            <div class="metric-value medium">${mediumSeverityCount}</div>
            <div>Medium Severity</div>
        </div>
        <div class="metric">
            <div class="metric-value low">${lowSeverityCount}</div>
            <div>Low Severity</div>
        </div>
    </div>

    ${totalIssues === 0 ? `
        <div class="no-issues">
            <div class="shield-icon">🛡️</div>
            <h2>No Security Issues Found!</h2>
            <p>Your code appears to be free of the common security vulnerabilities we check for.</p>
        </div>
    ` : reports.map(report => `
        <div class="file-report">
            <div class="file-header">
                📄 ${report.fileName} (${report.issues.length} issue${report.issues.length !== 1 ? 's' : ''})
            </div>
            ${report.issues.map(issue => `
                <div class="issue">
                    <div class="issue-header">
                        <span class="line-number">Line ${issue.line}</span>
                        <span class="severity-badge severity-${issue.severity.toLowerCase()}">${issue.severity}</span>
                    </div>
                    <div class="issue-description">${issue.issue}</div>
                </div>
            `).join('')}
        </div>
    `).join('')}
</body>
</html>`;
    }

    public dispose(): void {
        if (this.panel) {
            this.panel.dispose();
        }
    }
}