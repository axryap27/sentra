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

interface FileCache {
    path: string;
    lastModified: number;
    contentHash: string;
    issues: SecurityIssue[];
}

export class SecurityAnalyzer {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private context: vscode.ExtensionContext;
    private pythonAnalyzerPath: string;
    private lastWorkspaceReport: SecurityReport[] = [];
    private fileCache: Map<string, FileCache> = new Map();
    private readonly crypto = require('crypto');

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securityAnalyzer');
        
        // Path to the Python analyzer script
        this.pythonAnalyzerPath = path.join(context.extensionPath, 'backend', 'analyzer.py');
        
        // Load cache from persistent storage
        this.loadCache();
        
        context.subscriptions.push(this.diagnosticCollection);
    }

    async scanFile(uri: vscode.Uri): Promise<void> {
        if (!this.isSupportedLanguage(uri.fsPath)) {
            return;
        }

        try {
            const document = await vscode.workspace.openTextDocument(uri);
            const content = document.getText();
            
            // Check if incremental scanning is enabled and file has changed
            const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
            const incrementalEnabled = config.get<boolean>('enableIncrementalScanning', true);
            const hasChanged = !incrementalEnabled || await this.isFileChanged(uri.fsPath, content);
            
            let issues: SecurityIssue[];
            
            if (!hasChanged) {
                // Use cached results
                const cached = this.fileCache.get(uri.fsPath);
                issues = cached?.issues || [];
                console.log(`Using cached results for ${path.basename(uri.fsPath)}`);
            } else {
                // Analyze file and update cache
                issues = await this.analyzeFile(content, uri.fsPath);
                await this.updateFileCache(uri.fsPath, content, issues);
                console.log(`Analyzed ${path.basename(uri.fsPath)} - found ${issues.length} issues`);
            }
            
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

        // Find all supported source code files in workspace
        const supportedFiles = await this.findSupportedFiles();
        
        if (supportedFiles.length === 0) {
            vscode.window.showInformationMessage('No supported source code files found in workspace');
            return null;
        }

        const reports: SecurityReport[] = [];

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
                    
                    // Check if incremental scanning is enabled and file has changed
                    const incrementalEnabled = vscode.workspace.getConfiguration('secureCodeAnalyzer').get<boolean>('enableIncrementalScanning', true);
                    const hasChanged = !incrementalEnabled || await this.isFileChanged(file.fsPath, content);
                    
                    let issues: SecurityIssue[];
                    
                    if (!hasChanged) {
                        // Use cached results
                        const cached = this.fileCache.get(file.fsPath);
                        issues = cached?.issues || [];
                    } else {
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
                vscode.window.showInformationMessage(`Workspace scan completed. Scanned ${processed} source code files.`);
            }
        });

        this.lastWorkspaceReport = reports;
        return reports;
    }

    private isSupportedLanguage(filePath: string): boolean {
        const ext = path.extname(filePath).toLowerCase();
        const supportedExtensions = [
            '.py',      // Python
            '.js',      // JavaScript
            '.jsx',     // React JSX
            '.ts',      // TypeScript
            '.tsx',     // React TSX
            '.java',    // Java
            '.c',       // C
            '.cpp',     // C++
            '.cc',      // C++
            '.cxx',     // C++
            '.hpp',     // C++ header
            '.h',       // C/C++ header
            '.go',      // Go
            '.php',     // PHP
            '.cs',      // C#
            '.rs'       // Rust
        ];
        return supportedExtensions.includes(ext);
    }

    private async findSupportedFiles(): Promise<vscode.Uri[]> {
        const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
        const excludePatterns = config.get<string[]>('excludePatterns', [
            '**/node_modules/**', 
            '**/test/**', 
            '**/tests/**', 
            '**/__pycache__/**',
            '**/target/**',        // Java/Rust builds
            '**/build/**',         // Build directories
            '**/dist/**',          // Distribution directories
            '**/.git/**',          // Git directories
            '**/vendor/**',        // Go/PHP vendor
            '**/bin/**',           // Binary directories
            '**/obj/**'            // C# object files
        ]);
        
        const patterns = [
            '**/*.py', '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx',
            '**/*.java', '**/*.c', '**/*.cpp', '**/*.cc', '**/*.cxx',
            '**/*.hpp', '**/*.h', '**/*.go', '**/*.php', '**/*.cs', '**/*.rs'
        ];
        
        // Create exclusion pattern
        const excludePattern = `{${excludePatterns.join(',')}}`;
        
        const allFiles: vscode.Uri[] = [];
        for (const pattern of patterns) {
            const files = await vscode.workspace.findFiles(pattern, excludePattern);
            allFiles.push(...files);
        }
        
        // Remove duplicates and filter by file size (skip very large files)
        const uniqueFiles = allFiles.filter((file, index, self) => 
            index === self.findIndex(f => f.fsPath === file.fsPath)
        );
        
        // Filter out files that are too large (configurable limit)
        const maxFileSize = config.get<number>('maxFileSize', 1024 * 1024); // 1MB default
        const filteredFiles: vscode.Uri[] = [];
        
        for (const file of uniqueFiles) {
            try {
                const fs = require('fs');
                const stats = await fs.promises.stat(file.fsPath);
                if (stats.size <= maxFileSize) {
                    filteredFiles.push(file);
                } else {
                    console.log(`Skipping large file: ${file.fsPath} (${Math.round(stats.size / 1024)}KB)`);
                }
            } catch (error) {
                // If we can't stat the file, skip it
                console.warn(`Could not stat file: ${file.fsPath}`, error);
            }
        }
        
        return filteredFiles;
    }

    private async analyzeFile(code: string, filePath: string): Promise<SecurityIssue[]> {
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
        this.saveCache();
    }

    private generateContentHash(content: string): string {
        return this.crypto.createHash('md5').update(content).digest('hex');
    }

    private async loadCache(): Promise<void> {
        try {
            const cacheData = this.context.globalState.get<{ [key: string]: FileCache }>('sentra.fileCache', {});
            this.fileCache = new Map(Object.entries(cacheData));
        } catch (error) {
            console.warn('Failed to load cache:', error);
            this.fileCache = new Map();
        }
    }

    private async saveCache(): Promise<void> {
        try {
            const cacheData = Object.fromEntries(this.fileCache);
            await this.context.globalState.update('sentra.fileCache', cacheData);
        } catch (error) {
            console.warn('Failed to save cache:', error);
        }
    }

    private async isFileChanged(filePath: string, content: string): Promise<boolean> {
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
        } catch (error) {
            // If we can't stat the file, consider it changed
            return true;
        }
    }

    private async updateFileCache(filePath: string, content: string, issues: SecurityIssue[]): Promise<void> {
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
        } catch (error) {
            console.warn('Failed to update cache for', filePath, error);
        }
    }
}