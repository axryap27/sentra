import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityAnalyzer } from './analyzer';
import { SecurityStatusBar } from './statusBar';
import { SecurityReportPanel } from './webviewPanel';

let analyzer: SecurityAnalyzer;
let statusBar: SecurityStatusBar;
let reportPanel: SecurityReportPanel;

export function activate(context: vscode.ExtensionContext) {
    console.log('Secure Code Analyzer extension is now active');

    // Initialize components
    analyzer = new SecurityAnalyzer(context);
    statusBar = new SecurityStatusBar();
    reportPanel = new SecurityReportPanel(context);

    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('secureCodeAnalyzer.scanFile', async (uri?: vscode.Uri) => {
        const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
        if (targetUri) {
            await analyzer.scanFile(targetUri);
        } else {
            vscode.window.showWarningMessage('No file selected for scanning');
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('secureCodeAnalyzer.scanWorkspace', async () => {
        const reports = await analyzer.scanWorkspace();
        if (reports) {
            reportPanel.showReport(reports);
            const totalIssues = reports.reduce((sum, report) => sum + report.issues.length, 0);
            statusBar.updateIssueCount(totalIssues);
        }
    });

    const showReportCommand = vscode.commands.registerCommand('secureCodeAnalyzer.showReport', async () => {
        const reports = await analyzer.getLastWorkspaceReport();
        if (reports) {
            reportPanel.showReport(reports);
        } else {
            vscode.window.showInformationMessage('No security report available. Run a workspace scan first.');
        }
    });

    const clearDiagnosticsCommand = vscode.commands.registerCommand('secureCodeAnalyzer.clearDiagnostics', () => {
        analyzer.clearAllDiagnostics();
    });

    // Register file save listener for auto-scan
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        if (config.get('autoScan') && config.get('enabled') && document.languageId === 'python') {
            await analyzer.scanFile(document.uri);
        }
    });

    // Register file open listener
    const onOpenDisposable = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        if (config.get('enabled') && document.languageId === 'python') {
            await analyzer.scanFile(document.uri);
        }
    });

    // Add to context subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        showReportCommand,
        clearDiagnosticsCommand,
        onSaveDisposable,
        onOpenDisposable,
        statusBar
    );

    // Show activation message
    vscode.window.showInformationMessage('Secure Code Analyzer is ready!');
}

export function deactivate() {
    if (analyzer) {
        analyzer.dispose();
    }
    if (statusBar) {
        statusBar.dispose();
    }
    if (reportPanel) {
        reportPanel.dispose();
    }
}