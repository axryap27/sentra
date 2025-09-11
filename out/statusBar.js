"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityStatusBar = void 0;
const vscode = require("vscode");
class SecurityStatusBar {
    constructor() {
        this.issueCount = 0;
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.statusBarItem.command = 'secureCodeAnalyzer.scanWorkspace';
        this.updateStatusBar();
        this.statusBarItem.show();
    }
    updateIssueCount(count) {
        this.issueCount = count;
        this.updateStatusBar();
    }
    updateStatusBar() {
        if (this.issueCount === 0) {
            this.statusBarItem.text = '$(shield) Security: Clean';
            this.statusBarItem.tooltip = 'No security issues found. Click to scan workspace.';
            this.statusBarItem.backgroundColor = undefined;
        }
        else {
            this.statusBarItem.text = `$(alert) Security: ${this.issueCount} issue${this.issueCount > 1 ? 's' : ''}`;
            this.statusBarItem.tooltip = `${this.issueCount} security issue${this.issueCount > 1 ? 's' : ''} found. Click to scan workspace.`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        }
    }
    dispose() {
        this.statusBarItem.dispose();
    }
}
exports.SecurityStatusBar = SecurityStatusBar;
//# sourceMappingURL=statusBar.js.map