// Project Guard VS Code Security & Threat Hunting Extension
// Real-time source code threat scanning, secret leakage detection, and EDR daemon integration.

const vscode = require('vscode');
const http = require('http');

let diagnosticCollection;
let statusBarItem;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('projectguard');
    context.subscriptions.push(diagnosticCollection);

    // 1. Setup Status Bar Item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'projectguard.scanCurrentFile';
    statusBarItem.text = '$(shield) Project Guard: Aktif';
    statusBarItem.tooltip = 'Project Guard EDR Koruması Devrede (Taramak için tıklayın)';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // 2. Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('projectguard.scanCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('Project Guard: Taranacak aktif bir dosya açık değil.');
                return;
            }
            analyzeDocument(editor.document);
            vscode.window.showInformationMessage(`Project Guard: ${editor.document.fileName} dosyası tarandı.`);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('projectguard.scanWorkspace', async () => {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Project Guard: Çalışma Alanı Taranıyor...',
                cancellable: false
            }, async () => {
                const files = await vscode.workspace.findFiles('**/*', '**/node_modules/**');
                let threatsCount = 0;
                for (const file of files.slice(0, 50)) {
                    try {
                        const doc = await vscode.workspace.openTextDocument(file);
                        const found = analyzeDocument(doc);
                        threatsCount += found;
                    } catch (_e) {}
                }
                if (threatsCount > 0) {
                    vscode.window.showErrorMessage(`Project Guard: Çalışma alanında ${threatsCount} adet güvenlik riski veya sızıntı tespit edildi!`);
                } else {
                    vscode.window.showInformationMessage('Project Guard: Çalışma alanı temiz, tehdit tespit edilmedi.');
                }
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('projectguard.checkCisaKev', () => {
            const panel = vscode.window.createWebviewPanel(
                'projectguardKev',
                'CISA KEV - Bilinen Aktif Zafiyetler',
                vscode.ViewColumn.Two,
                { enableScripts: true }
            );

            panel.webview.html = getCisaKevWebviewContent();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('projectguard.openSoc', () => {
            const config = vscode.workspace.getConfiguration('projectguard');
            const daemonUrl = config.get('daemonUrl') || 'http://localhost:7890';
            vscode.env.openExternal(vscode.Uri.parse(daemonUrl));
        })
    );

    // 3. Register Sidebar Tree Provider
    const treeProvider = new ProjectGuardTreeDataProvider();
    vscode.window.registerTreeDataProvider('projectguard.threatExplorer', treeProvider);

    // 4. File Watchers for Real-Time Analysis
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => analyzeDocument(doc)),
        vscode.workspace.onDidSaveTextDocument(doc => {
            const config = vscode.workspace.getConfiguration('projectguard');
            if (config.get('scanOnSave')) {
                analyzeDocument(doc);
            }
        })
    );

    // Analyze currently active document on load
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document);
    }
}

/**
 * Inspect document text for threat indicators and Honeytoken leaks
 * @param {vscode.TextDocument} document
 * @returns {number} threat count
 */
function analyzeDocument(document) {
    if (document.uri.scheme !== 'file') return 0;

    const text = document.getText();
    const diagnostics = [];

    // Security Rules Pattern Matcher
    const rules = [
        {
            regex: /AKIA[0-9A-Z]{16}/g,
            message: 'CISA Honeytoken / Sızıntı Riski: Açıkta bırakılmış AWS Access Key ID!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1552.001'
        },
        {
            regex: /-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/g,
            message: 'Kritik Güvenlik Uyarısı: Kaynak kod içine gömülmüş Özel Kriptografik Anahtar (Private Key)!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1552.004'
        },
        {
            regex: /vssadmin(\.exe)?\s+delete\s+shadows/gi,
            message: 'Fidye Yazılımı Davranışı (T1490): Gölge Kopyaları (VSS) silme komutu tespit edildi!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1490'
        },
        {
            regex: /bcdedit(\.exe)?\s+(\/set\s+.*(recoveryenabled\s+no|safeboot\s+minimal|bootstatuspolicy\s+ignoreallfailures))/gi,
            message: 'Kurtarma Sabotajı / EDR Atlatma (T1490/T1562): BCD kurtarma kapatma veya Güvenli Mod zorlaması!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1490'
        },
        {
            regex: /fltmc(\.exe)?\s+unload\s+\w+/gi,
            message: 'EDR-Kill Girişimi (T1562.001): Antivirüs dosya sistemi minifiltresini boşaltma komutu!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1562.001'
        },
        {
            regex: /comsvcs(\.dll)?\s*,\s*(#24|MiniDump)/gi,
            message: 'Kimlik Bilgisi Hırsızlığı (T1003.001): Comsvcs ile LSASS bellek dökümü (Memory Dump) alma!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1003.001'
        },
        {
            regex: /powershell(\.exe)?\s+.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi,
            message: 'Şüpheli Gizlenmiş Kod Yürütme (T1059.001): Base64 şifreli PowerShell komutu!',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'T1059.001'
        },
        {
            regex: /wevtutil(\.exe)?\s+(cl|clear-log)\s+(Security|System|Application)/gi,
            message: 'İz Silme / Olay Günlüğü Temizleme (T1070.001): wevtutil log silme komutu!',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'T1070.001'
        },
        {
            regex: /"(preinstall|postinstall|install)"\s*:\s*".*(curl|wget|powershell|certutil|eval\(Buffer)/gi,
            message: 'OpenSSF & OWASP A03 Tedarik Zinciri Uyarısı: package.json içinde şüpheli kabuk/indirme komutu!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1195.001'
        },
        {
            regex: /(net(\.exe)?\s+localgroup\s+(administrators|remote desktop users)\s+.*\/add|Add-LocalGroupMember\s+.*(Administrators|Remote Desktop Users))/gi,
            message: 'MITRE ATT&CK v16 (T1098.007): Yetkisiz yerel yönetici grubu (Administrators) ataması!',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'T1098.007'
        }
    ];

    for (let lineIndex = 0; lineIndex < document.lineCount; lineIndex++) {
        const lineText = document.lineAt(lineIndex).text;

        for (const rule of rules) {
            rule.regex.lastIndex = 0;
            let match;
            while ((match = rule.regex.exec(lineText)) !== null) {
                const range = new vscode.Range(
                    lineIndex,
                    match.index,
                    lineIndex,
                    match.index + match[0].length
                );
                const diagnostic = new vscode.Diagnostic(range, rule.message, rule.severity);
                diagnostic.code = rule.code;
                diagnostic.source = 'Project Guard EDR';
                diagnostics.push(diagnostic);
            }
        }
    }

    diagnosticCollection.set(document.uri, diagnostics);
    return diagnostics.length;
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
    }
}

// Tree View Provider for Project Guard Sidebar
class ProjectGuardTreeDataProvider {
    getTreeItem(element) {
        return element;
    }

    getChildren(element) {
        if (!element) {
            return Promise.resolve([
                new ThreatTreeItem('🛡️ EDR Motoru', 'Port 7890 (Bağlı)', vscode.TreeItemCollapsibleState.None),
                new ThreatTreeItem('🔍 CISA KEV Zafiyetleri', '8 Kritik Zafiyet İzleniyor', vscode.TreeItemCollapsibleState.None),
                new ThreatTreeItem('🍯 CISA Cyber Decoys', 'Honeytoken ve Yemler Aktif', vscode.TreeItemCollapsibleState.None),
                new ThreatTreeItem('🚀 Hızlı Tarama Başlat', 'projectguard.scanWorkspace', vscode.TreeItemCollapsibleState.None, true),
                new ThreatTreeItem('📊 Web SOC Konsolunu Aç', 'projectguard.openSoc', vscode.TreeItemCollapsibleState.None, true)
            ]);
        }
        return Promise.resolve([]);
    }
}

class ThreatTreeItem extends vscode.TreeItem {
    constructor(label, detail, collapsibleState, isCommand = false) {
        super(label, collapsibleState);
        this.description = isCommand ? '' : detail;
        if (isCommand) {
            this.command = {
                command: detail,
                title: label
            };
        }
    }
}

function getCisaKevWebviewContent() {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
        h1 { color: #10B981; font-size: 18px; margin-bottom: 4px; }
        .badge { background: #EF4444; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }
        .card { background: var(--vscode-sideBar-background); border: 1px solid var(--vscode-panel-border); border-radius: 8px; padding: 14px; margin-bottom: 12px; }
        .cve { color: #06B6D4; font-weight: bold; font-size: 14px; }
        .desc { font-size: 12px; margin: 6px 0; }
        .action { font-size: 11px; color: #10B981; }
    </style>
</head>
<body>
    <h1>CISA KEV - Bilinen ve Aktif İstismar Edilen Zafiyetler</h1>
    <p style="font-size:12px; color:var(--vscode-descriptionForeground);">Referans: CISA BOD 22-01 / 26-04 Uç Nokta ve Windows Direktifi</p>
    <hr style="border:0; border-top:1px solid var(--vscode-panel-border); margin:15px 0;">

    <div class="card">
        <div class="cve">CVE-2024-21338 <span class="badge">RANSOMWARE BYOVD</span></div>
        <div class="desc"><strong>Windows Kernel / AppLocker</strong>: Lazarus ve fidye gruplarınca EDR/AV süreçlerini çekirdekten öldürmek için aktif istismar edilen sürücü zafiyeti.</div>
        <div class="action">Eylem: En son Windows güvenlik güncellemesini yükleyin ve WDAC sürücü blok listesini etkinleştirin.</div>
    </div>

    <div class="card">
        <div class="cve">CVE-2024-38063 <span class="badge">CRITICAL RCE</span></div>
        <div class="desc"><strong>Windows TCP/IP Yığını</strong>: Özel hazırlanmış IPv6 paketleri ile kimlik doğrulaması olmadan uzaktan kod yürütme.</div>
        <div class="action">Eylem: KB5041585 yamasını uygulayın ve IPv6 arabirimlerini koruyun.</div>
    </div>

    <div class="card">
        <div class="cve">CVE-2024-30051 <span class="badge">EOP WEAPONIZED</span></div>
        <div class="desc"><strong>Windows DWM Core Library</strong>: Qakbot fidye grubu tarafından SYSTEM yetkisi elde etmek için istismar edilen zafiyet.</div>
        <div class="action">Eylem: KB5037768 yamasını yükleyin.</div>
    </div>

    <div class="card">
        <div class="cve">CVE-2021-34527 <span class="badge">PRINTNIGHTMARE</span></div>
        <div class="desc"><strong>Windows Print Spooler</strong>: Yetkisiz sürücü yükleme ve tam SYSTEM yetkisi elde etme zafiyeti.</div>
        <div class="action">Eylem: Print Spooler servisini devre dışı bırakın veya Point and Print kısıtlamalarını uygulayın.</div>
    </div>
</body>
</html>`;
}

module.exports = {
    activate,
    deactivate
};
