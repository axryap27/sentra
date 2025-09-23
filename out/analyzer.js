"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityAnalyzer = void 0;
const vscode = require("vscode");
const path = require("path");
const child_process_1 = require("child_process");
const util_1 = require("util");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
class SecurityAnalyzer {
    constructor(context) {
        this.lastWorkspaceReport = [];
        this.fileCache = new Map();
        this.crypto = require('crypto');
        this.context = context;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securityAnalyzer');
        // Path to the Python analyzer script
        this.pythonAnalyzerPath = path.join(context.extensionPath, 'backend', 'analyzer.py');
        // Load cache from persistent storage
        this.loadCache();
        context.subscriptions.push(this.diagnosticCollection);
    }
    async scanFile(uri) {
        if (!this.isSupportedLanguage(uri.fsPath)) {
            return;
        }
        try {
            const document = await vscode.workspace.openTextDocument(uri);
            const content = document.getText();
            // Check if file has changed since last analysis
            const hasChanged = await this.isFileChanged(uri.fsPath, content);
            let issues;
            if (!hasChanged) {
                // Use cached results
                const cached = this.fileCache.get(uri.fsPath);
                issues = cached?.issues || [];
                console.log(`Using cached results for ${path.basename(uri.fsPath)}`);
            }
            else {
                // Analyze file and update cache
                issues = await this.analyzeFile(content, uri.fsPath);
                await this.updateFileCache(uri.fsPath, content, issues);
                console.log(`Analyzed ${path.basename(uri.fsPath)} - found ${issues.length} issues`);
            }
            this.updateDiagnostics(uri, issues);
        }
        catch (error) {
            console.error('Error scanning file:', error);
            vscode.window.showErrorMessage(`Failed to scan file: ${error}`);
        }
    }
    async scanWorkspace() {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        if (!config.get('enabled')) {
            return null;
        }
        // Find all supported source code files in workspace
        const supportedFiles = await this.findSupportedFiles();
        if (supportedFiles.length === 0) {
            vscode.window.showInformationMessage('No supported source code files found in workspace');
            return null;
        }
        const reports = [];
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Scanning workspace for security vulnerabilities...',
            cancellable: true
        }, async (progress, token) => {
            const total = supportedFiles.length;
            let processed = 0;
            for (const file of supportedFiles) {
                if (token.isCancellationRequested) {
                    break;
                }
                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const content = document.getText();
                    // Check if file has changed since last analysis
                    const hasChanged = await this.isFileChanged(file.fsPath, content);
                    let issues;
                    if (!hasChanged) {
                        // Use cached results
                        const cached = this.fileCache.get(file.fsPath);
                        issues = cached?.issues || [];
                    }
                    else {
                        // Analyze file and update cache
                        issues = await this.analyzeFile(content, file.fsPath);
                        await this.updateFileCache(file.fsPath, content, issues);
                    }
                    this.updateDiagnostics(file, issues);
                    if (issues.length > 0) {
                        reports.push({
                            fileName: vscode.workspace.asRelativePath(file),
                            issues: issues
                        });
                    }
                }
                catch (error) {
                    console.error(`Error scanning ${file.fsPath}:`, error);
                }
                processed++;
                progress.report({
                    increment: (100 / total),
                    message: `${processed}/${total} files scanned`
                });
            }
            if (!token.isCancellationRequested) {
                vscode.window.showInformationMessage(`Workspace scan completed. Scanned ${processed} source code files.`);
            }
        });
        this.lastWorkspaceReport = reports;
        return reports;
    }
    isSupportedLanguage(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const supportedExtensions = [
            '.py',
            '.js',
            '.jsx',
            '.ts',
            '.tsx',
            '.java',
            '.c',
            '.cpp',
            '.cc',
            '.cxx',
            '.hpp',
            '.h',
            '.go',
            '.php',
            '.cs',
            '.rs' // Rust
        ];
        return supportedExtensions.includes(ext);
    }
    async findSupportedFiles() {
        const patterns = [
            '**/*.py', '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx',
            '**/*.java', '**/*.c', '**/*.cpp', '**/*.cc', '**/*.cxx',
            '**/*.hpp', '**/*.h', '**/*.go', '**/*.php', '**/*.cs', '**/*.rs'
        ];
        const allFiles = [];
        for (const pattern of patterns) {
            const files = await vscode.workspace.findFiles(pattern, '**/node_modules/**');
            allFiles.push(...files);
        }
        // Remove duplicates
        const uniqueFiles = allFiles.filter((file, index, self) => index === self.findIndex(f => f.fsPath === file.fsPath));
        return uniqueFiles;
    }
    async analyzeFile(code, filePath) {
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
            }
            catch (buildError) {
                console.error('Failed to build Go analyzer:', buildError);
                throw new Error('Failed to build security analyzer');
            }
        }
        try {
            // Write code to temporary file with appropriate extension
            const os = require('os');
            const fileExt = path.extname(filePath);
            const tempFile = path.join(os.tmpdir(), `sentra_analyzer_${Date.now()}${fileExt}`);
            await fs.promises.writeFile(tempFile, code, 'utf8');
            const { stdout, stderr } = await execAsync(`"${binaryPath}" --file "${tempFile}" --format json`, {
                cwd: this.context.extensionPath,
                timeout: 30000 // 30 second timeout
            });
            // Clean up temp file
            try {
                await fs.promises.unlink(tempFile);
            }
            catch (cleanupError) {
                console.warn('Failed to clean up temp file:', cleanupError);
            }
            if (stderr) {
                console.warn('Go analyzer stderr:', stderr);
            }
            const issues = JSON.parse(stdout.trim() || '[]');
            return this.filterIssuesBySeverity(issues);
        }
        catch (error) {
            console.error('Go analyzer error:', error);
            throw new Error(`AI analysis failed: ${error}`);
        }
    }
    filterIssuesBySeverity(issues) {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        const minSeverity = config.get('severityLevel', 'Medium');
        const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        const minLevel = severityOrder[minSeverity] || 2;
        return issues.filter(issue => {
            const issueLevel = severityOrder[issue.severity] || 0;
            return issueLevel >= minLevel;
        });
    }
    updateDiagnostics(uri, issues) {
        const diagnostics = issues.map(issue => {
            const range = new vscode.Range(Math.max(0, issue.line - 1), // VS Code lines are 0-based
            0, Math.max(0, issue.line - 1), Number.MAX_VALUE);
            const severity = this.getSeverityLevel(issue.severity);
            const diagnostic = new vscode.Diagnostic(range, issue.issue, severity);
            diagnostic.source = 'Sentra';
            diagnostic.code = issue.severity.toLowerCase();
            return diagnostic;
        });
        this.diagnosticCollection.set(uri, diagnostics);
    }
    getSeverityLevel(severity) {
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
    getLastWorkspaceReport() {
        return this.lastWorkspaceReport.length > 0 ? this.lastWorkspaceReport : null;
    }
    clearAllDiagnostics() {
        this.diagnosticCollection.clear();
        vscode.window.showInformationMessage('Security diagnostics cleared');
    }
    dispose() {
        this.diagnosticCollection.dispose();
        this.saveCache();
    }
    generateContentHash(content) {
        return this.crypto.createHash('md5').update(content).digest('hex');
    }
    async loadCache() {
        try {
            const cacheData = this.context.globalState.get('sentra.fileCache', {});
            this.fileCache = new Map(Object.entries(cacheData));
        }
        catch (error) {
            console.warn('Failed to load cache:', error);
            this.fileCache = new Map();
        }
    }
    async saveCache() {
        try {
            const cacheData = Object.fromEntries(this.fileCache);
            await this.context.globalState.update('sentra.fileCache', cacheData);
        }
        catch (error) {
            console.warn('Failed to save cache:', error);
        }
    }
    async isFileChanged(filePath, content) {
        const fs = require('fs');
        try {
            const stats = await fs.promises.stat(filePath);
            const lastModified = stats.mtimeMs;
            const contentHash = this.generateContentHash(content);
            const cached = this.fileCache.get(filePath);
            if (!cached) {
                return true; // File not in cache, consider it changed
            }
            // Check if file has been modified or content has changed
            return cached.lastModified !== lastModified || cached.contentHash !== contentHash;
        }
        catch (error) {
            // If we can't stat the file, consider it changed
            return true;
        }
    }
    async updateFileCache(filePath, content, issues) {
        const fs = require('fs');
        try {
            const stats = await fs.promises.stat(filePath);
            const lastModified = stats.mtimeMs;
            const contentHash = this.generateContentHash(content);
            this.fileCache.set(filePath, {
                path: filePath,
                lastModified,
                contentHash,
                issues: [...issues] // Create a copy to avoid reference issues
            });
        }
        catch (error) {
            console.warn('Failed to update cache for', filePath, error);
        }
    }
}
exports.SecurityAnalyzer = SecurityAnalyzer;
//# sourceMappingURL=analyzer.js.map