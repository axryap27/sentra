"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = require("vscode");
const analyzer_1 = require("./analyzer");
const statusBar_1 = require("./statusBar");
const webviewPanel_1 = require("./webviewPanel");
let analyzer;
let statusBar;
let reportPanel;
function activate(context) {
    console.log('Sentra extension is now active');
    // Initialize components
    analyzer = new analyzer_1.SecurityAnalyzer(context);
    statusBar = new statusBar_1.SecurityStatusBar();
    reportPanel = new webviewPanel_1.SecurityReportPanel(context);
    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('secureCodeAnalyzer.scanFile', async (uri) => {
        const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
        if (targetUri) {
            await analyzer.scanFile(targetUri);
        }
        else {
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
        }
        else {
            vscode.window.showInformationMessage('No security report available. Run a workspace scan first.');
        }
    });
    const clearDiagnosticsCommand = vscode.commands.registerCommand('secureCodeAnalyzer.clearDiagnostics', () => {
        analyzer.clearAllDiagnostics();
    });
    // Register file save listener for auto-scan
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'go', 'php', 'csharp', 'rust'];
        if (config.get('autoScan') && config.get('enabled') && supportedLanguages.includes(document.languageId)) {
            await analyzer.scanFile(document.uri);
        }
    });
    // Register file open listener
    const onOpenDisposable = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'go', 'php', 'csharp', 'rust'];
        if (config.get('enabled') && supportedLanguages.includes(document.languageId)) {
            await analyzer.scanFile(document.uri);
        }
    });
    // Add to context subscriptions
    context.subscriptions.push(scanFileCommand, scanWorkspaceCommand, showReportCommand, clearDiagnosticsCommand, onSaveDisposable, onOpenDisposable, statusBar);
    // Show activation message
    vscode.window.showInformationMessage('Sentra is ready!');
}
exports.activate = activate;
function deactivate() {
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
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map