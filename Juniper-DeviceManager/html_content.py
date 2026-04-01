"""
Embedded HTML/CSS/JavaScript SPA for Juniper Device Manager.
"""

HTML_CONTENT = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Juniper Device Manager</title>
<style>
:root {
    --bg: #0f172a; --bg-card: #1e293b; --bg-card-hover: #263348;
    --bg-input: #334155; --bg-sidebar: #0c1322;
    --text: #e2e8f0; --text-muted: #94a3b8; --text-heading: #f1f5f9;
    --border: #334155;
    --accent: #38bdf8; --accent-hover: #7dd3fc; --accent-dim: rgba(56,189,248,0.15);
    --success: #34d399; --success-dim: rgba(52,211,153,0.15);
    --warning: #fbbf24; --warning-dim: rgba(251,191,36,0.15);
    --danger: #f87171; --danger-dim: rgba(248,113,113,0.15);
    --radius: 8px; --shadow: 0 1px 3px rgba(0,0,0,0.4);
    --font-mono: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}
[data-theme="light"] {
    --bg: #f1f5f9; --bg-card: #fff; --bg-card-hover: #f8fafc;
    --bg-input: #e2e8f0; --bg-sidebar: #e2e8f0;
    --text: #1e293b; --text-muted: #64748b; --text-heading: #0f172a;
    --border: #cbd5e1;
    --accent: #0284c7; --accent-hover: #0369a1; --accent-dim: rgba(2,132,199,0.1);
    --success: #059669; --success-dim: rgba(5,150,105,0.1);
    --warning: #d97706; --warning-dim: rgba(217,119,6,0.1);
    --danger: #dc2626; --danger-dim: rgba(220,38,38,0.1);
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column;overflow:hidden;}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:56px;background:var(--bg-sidebar);border-bottom:1px solid var(--border);flex-shrink:0;}
.topbar-left{display:flex;align-items:center;gap:14px;}
.topbar-logo{font-size:18px;font-weight:700;color:var(--accent);letter-spacing:-0.5px;}
.topbar-logo span{color:var(--text-muted);font-weight:400;font-size:13px;margin-left:6px;}
.topbar-right{display:flex;align-items:center;gap:12px;}
.lock-badge{display:flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;}
.lock-badge.locked{background:var(--danger-dim);color:var(--danger);}
.lock-badge.unlocked{background:var(--success-dim);color:var(--success);}
.lock-dot{width:8px;height:8px;border-radius:50%;background:currentColor;}
.btn-sm{background:transparent;border:1px solid var(--border);color:var(--text-muted);padding:6px 12px;border-radius:var(--radius);cursor:pointer;font-size:12px;transition:all 0.2s;}
.btn-sm:hover{border-color:var(--accent);color:var(--accent);}
.theme-toggle{background:var(--bg-input);border:1px solid var(--border);color:var(--text);width:36px;height:36px;border-radius:50%;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all 0.2s;}
.theme-toggle:hover{border-color:var(--accent);}
.main-layout{display:flex;flex:1;overflow:hidden;}
.sidebar{width:220px;background:var(--bg-sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;padding:12px 0;}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;color:var(--text-muted);cursor:pointer;font-size:13px;font-weight:500;transition:all 0.15s;border-left:3px solid transparent;user-select:none;}
.nav-item:hover{color:var(--text);background:var(--bg-card);}
.nav-item.active{color:var(--accent);background:var(--accent-dim);border-left-color:var(--accent);}
.nav-item.disabled{opacity:0.35;pointer-events:none;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.nav-label{flex:1;}
.nav-badge{font-size:10px;background:var(--bg-input);color:var(--text-muted);padding:2px 8px;border-radius:10px;font-weight:700;}
.nav-divider{height:1px;background:var(--border);margin:8px 20px;}
.sidebar-footer{margin-top:auto;padding:12px 20px;font-size:11px;color:var(--text-muted);border-top:1px solid var(--border);}
.content-area{flex:1;overflow-y:auto;padding:24px;}
.page{display:none;}
.page.active{display:block;}
.page-title{font-size:20px;font-weight:700;color:var(--text-heading);margin-bottom:4px;}
.page-subtitle{font-size:13px;color:var(--text-muted);margin-bottom:20px;}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:16px;box-shadow:var(--shadow);}
.card-title{font-size:14px;font-weight:600;color:var(--text-heading);margin-bottom:12px;}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
.summary-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center;}
.summary-card .number{font-size:28px;font-weight:700;font-family:var(--font-mono);}
.summary-card .label{font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);margin-top:4px;}
.form-group{margin-bottom:16px;}
.form-group label{display:block;font-size:13px;font-weight:500;color:var(--text);margin-bottom:6px;}
.form-group .hint{font-size:11px;color:var(--text-muted);margin-top:4px;}
input[type="text"],input[type="password"],input[type="number"],select,textarea{width:100%;padding:9px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:border-color 0.2s;}
input:focus,select:focus,textarea:focus{border-color:var(--accent);}
input::placeholder,textarea::placeholder{color:var(--text-muted);}
textarea{resize:vertical;font-family:var(--font-mono);font-size:13px;}
.form-row{display:flex;gap:12px;}
.form-row .form-group{flex:1;}
.checkbox-group{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;}
.checkbox-group input[type="checkbox"]{width:auto;cursor:pointer;}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all 0.2s;font-family:inherit;}
.btn:disabled{opacity:0.5;cursor:not-allowed;}
.btn-primary{background:var(--accent);color:#fff;}
.btn-primary:hover:not(:disabled){background:var(--accent-hover);}
.btn-success{background:var(--success);color:#fff;}
.btn-success:hover:not(:disabled){filter:brightness(1.1);}
.btn-danger{background:var(--danger);color:#fff;}
.btn-danger:hover:not(:disabled){filter:brightness(1.1);}
.btn-outline{background:transparent;border-color:var(--border);color:var(--text);}
.btn-outline:hover:not(:disabled){border-color:var(--accent);color:var(--accent);}
.btn-group{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap;}
.alert{padding:12px 16px;border-radius:6px;font-size:13px;margin-bottom:16px;display:none;line-height:1.5;}
.alert.show{display:block;}
.alert-success{background:var(--success-dim);color:var(--success);border:1px solid var(--success);}
.alert-danger{background:var(--danger-dim);color:var(--danger);border:1px solid var(--danger);}
.alert-warning{background:var(--warning-dim);color:var(--warning);border:1px solid var(--warning);}
.alert-info{background:var(--accent-dim);color:var(--accent);border:1px solid var(--accent);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:10px 12px;color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid var(--border);background:var(--bg-card);}
td{padding:10px 12px;border-bottom:1px solid var(--border);}
tr:hover td{background:var(--bg-card-hover);}
.status-badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;}
.status-online{background:var(--success-dim);color:var(--success);}
.status-offline,.status-timeout{background:var(--danger-dim);color:var(--danger);}
.status-auth_failed{background:var(--warning-dim);color:var(--warning);}
.status-unknown{background:var(--bg-input);color:var(--text-muted);}
.config-viewer{background:#0a0e17;border:1px solid var(--border);border-radius:var(--radius);padding:16px;font-family:var(--font-mono);font-size:13px;line-height:1.5;color:#e2e8f0;max-height:500px;overflow:auto;white-space:pre-wrap;word-break:break-all;}
[data-theme="light"] .config-viewer{background:#1e293b;}
.diff-add{color:var(--success);background:var(--success-dim);}
.diff-del{color:var(--danger);background:var(--danger-dim);}
.diff-hdr{color:var(--accent);font-weight:700;}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.btn .spinner{width:12px;height:12px;}
.log-panel{height:180px;min-height:80px;background:#0a0e17;border-top:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;}
[data-theme="light"] .log-panel{background:#1e293b;}
.log-header{display:flex;align-items:center;justify-content:space-between;padding:6px 16px;background:rgba(0,0,0,0.2);border-bottom:1px solid rgba(255,255,255,0.06);}
.log-header-title{font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;}
.log-body{flex:1;overflow-y:auto;padding:8px 16px;font-family:var(--font-mono);font-size:12px;line-height:1.6;color:#cbd5e1;}
.log-entry{white-space:pre-wrap;word-break:break-all;}
.log-entry.INFO{color:#67e8f9;}
.log-entry.PASS{color:#6ee7b7;}
.log-entry.WARN{color:#fcd34d;}
.log-entry.FAIL{color:#fca5a5;}
.log-resize{height:4px;background:var(--border);cursor:ns-resize;}
.log-resize:hover{background:var(--accent);}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center;}
.overlay.show{display:flex;}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:28px;max-width:480px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.4);}
.modal-title{font-size:18px;font-weight:700;color:var(--text-heading);margin-bottom:16px;}
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:16px;}
.tab{padding:10px 20px;font-size:13px;font-weight:500;color:var(--text-muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.15s;}
.tab:hover{color:var(--text);}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-content{display:none;}
.tab-content.active{display:block;}
.device-select{max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:6px;padding:8px;}
.device-select label{display:flex;align-items:center;gap:8px;padding:4px 8px;font-size:13px;cursor:pointer;border-radius:4px;}
.device-select label:hover{background:var(--bg-card-hover);}
.progress-bar{height:6px;background:var(--bg-input);border-radius:3px;overflow:hidden;margin:8px 0;}
.progress-fill{height:100%;background:var(--accent);border-radius:3px;transition:width 0.3s;}
.progress-fill.indeterminate{width:30%;animation:indet 1.5s infinite ease-in-out;}
@keyframes indet{0%{margin-left:0%}50%{margin-left:70%}100%{margin-left:0%}}
</style>
</head>
<body>

<!-- LOCK OVERLAY -->
<div class="overlay" id="lockOverlay">
    <div class="modal">
        <div class="modal-title" id="authTitle">Unlock Session</div>
        <div id="authAlert" class="alert"></div>
        <div class="form-group">
            <label id="authLabel">Master Password</label>
            <input type="password" id="authPassword" placeholder="Enter master password" onkeydown="if(event.key==='Enter') doAuth()">
        </div>
        <div class="form-group" id="authConfirmGroup" style="display:none;">
            <label>Confirm Password</label>
            <input type="password" id="authConfirm" placeholder="Confirm password">
        </div>
        <div class="btn-group">
            <button id="btnAuth" class="btn btn-primary" onclick="doAuth()">Unlock</button>
        </div>
    </div>
</div>

<!-- TOP BAR -->
<div class="topbar">
    <div class="topbar-left">
        <div class="topbar-logo">Juniper Device Manager <span>VC3 Engineering</span></div>
    </div>
    <div class="topbar-right">
        <div id="lockBadge" class="lock-badge locked"><span class="lock-dot"></span><span id="lockText">Locked</span></div>
        <button class="btn-sm" id="btnLock" onclick="doLock()" style="display:none;">Lock</button>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">&#9681;</button>
        <button class="btn-sm" onclick="doShutdown()" style="color:var(--danger);">Shut Down</button>
    </div>
</div>

<!-- MAIN LAYOUT -->
<div class="main-layout">
<div class="sidebar">
    <div class="nav-item active" data-page="dashboard" onclick="showPage('dashboard')">
        <span class="nav-icon">&#9632;</span><span class="nav-label">Dashboard</span><span class="nav-badge" id="navDeviceCount">0</span>
    </div>
    <div class="nav-item" data-page="setup" onclick="showPage('setup')">
        <span class="nav-icon">&#9881;</span><span class="nav-label">Setup</span>
    </div>
    <div class="nav-divider"></div>
    <div class="nav-item" data-page="config" onclick="showPage('config')">
        <span class="nav-icon">&#128196;</span><span class="nav-label">Config</span>
    </div>
    <div class="nav-item" data-page="users" onclick="showPage('users')">
        <span class="nav-icon">&#128100;</span><span class="nav-label">Users</span>
    </div>
    <div class="nav-item" data-page="firmware" onclick="showPage('firmware')">
        <span class="nav-icon">&#11014;</span><span class="nav-label">Firmware</span>
    </div>
    <div class="nav-divider"></div>
    <div class="nav-item" data-page="log" onclick="showPage('log')">
        <span class="nav-icon">&#128203;</span><span class="nav-label">Activity Log</span>
    </div>
    <div class="sidebar-footer">
        <span id="sidebarInfo">Juniper Device Manager</span>
    </div>
</div>

<div style="flex:1;display:flex;flex-direction:column;overflow:hidden;">
<div class="content-area">

<!-- ====== DASHBOARD ====== -->
<div id="page-dashboard" class="page active">
    <div class="page-title">Device Inventory</div>
    <div class="page-subtitle">All discovered Juniper devices on the network.</div>
    <div class="summary-cards">
        <div class="summary-card"><div class="number" id="statTotal" style="color:var(--accent);">0</div><div class="label">Total</div></div>
        <div class="summary-card"><div class="number" id="statOnline" style="color:var(--success);">0</div><div class="label">Online</div></div>
        <div class="summary-card"><div class="number" id="statOffline" style="color:var(--danger);">0</div><div class="label">Offline</div></div>
        <div class="summary-card"><div class="number" id="statAuthFail" style="color:var(--warning);">0</div><div class="label">Auth Failed</div></div>
    </div>
    <div class="card">
        <div class="card-header">
            <div class="card-title" style="margin:0;">Devices</div>
            <div class="btn-group" style="margin:0;">
                <button class="btn btn-primary" onclick="runDiscovery()">Scan Subnets</button>
                <button class="btn btn-outline" onclick="refreshDashboard()">Refresh</button>
                <button class="btn btn-outline" onclick="window.open('/api/devices/export')">Export CSV</button>
            </div>
        </div>
        <div id="dashAlert" class="alert"></div>
        <div style="overflow-x:auto;">
            <table id="deviceTable">
                <thead><tr><th>Hostname</th><th>IP</th><th>Model</th><th>Firmware</th><th>Serial</th><th>Uptime</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody id="deviceTableBody"><tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:40px;">No devices discovered yet. Go to Setup to configure subnets, then click Scan Subnets.</td></tr></tbody>
            </table>
        </div>
    </div>
</div>

<!-- ====== SETUP ====== -->
<div id="page-setup" class="page">
    <div class="page-title">Setup</div>
    <div class="page-subtitle">Configure subnets and credentials for device discovery.</div>

    <div class="card">
        <div class="card-header"><div class="card-title" style="margin:0;">Subnets</div><button class="btn btn-outline" onclick="showAddSubnet()">Add Subnet</button></div>
        <div id="subnetAlert" class="alert"></div>
        <div id="addSubnetForm" style="display:none;margin-bottom:16px;">
            <div class="form-row">
                <div class="form-group"><label>CIDR</label><input type="text" id="newSubnetCidr" placeholder="192.168.99.0/24"></div>
                <div class="form-group"><label>Label</label><input type="text" id="newSubnetLabel" placeholder="Core Ring Management"></div>
            </div>
            <div class="btn-group" style="margin-top:8px;"><button class="btn btn-success" onclick="addSubnet()">Save</button><button class="btn btn-outline" onclick="hideAddSubnet()">Cancel</button></div>
        </div>
        <table id="subnetTable"><thead><tr><th>CIDR</th><th>Label</th><th>Actions</th></tr></thead><tbody id="subnetTableBody"></tbody></table>
    </div>

    <div class="card">
        <div class="card-header"><div class="card-title" style="margin:0;">Credential Groups</div><button class="btn btn-outline" onclick="showAddCred()">Add Credentials</button></div>
        <div id="credAlert" class="alert"></div>
        <div id="addCredForm" style="display:none;margin-bottom:16px;">
            <div class="form-row">
                <div class="form-group"><label>Name</label><input type="text" id="newCredName" placeholder="All Switches"></div>
                <div class="form-group"><label>Username</label><input type="text" id="newCredUser" placeholder="vc3admin"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>Password</label><input type="password" id="newCredPass" placeholder="Password"></div>
                <div class="form-group"><label>NETCONF Port</label><input type="number" id="newCredPort" value="830" placeholder="830"></div>
            </div>
            <div class="btn-group" style="margin-top:8px;"><button class="btn btn-success" onclick="addCred()">Save</button><button class="btn btn-outline" onclick="hideAddCred()">Cancel</button></div>
        </div>
        <table id="credTable"><thead><tr><th>Name</th><th>Username</th><th>Port</th><th>Actions</th></tr></thead><tbody id="credTableBody"></tbody></table>
    </div>
</div>

<!-- ====== CONFIG ====== -->
<div id="page-config" class="page">
    <div class="page-title">Configuration Management</div>
    <div class="page-subtitle">View, backup, compare, and push configs across devices.</div>
    <div class="tabs">
        <div class="tab active" onclick="showConfigTab('view')">View Config</div>
        <div class="tab" onclick="showConfigTab('backups')">Backups</div>
        <div class="tab" onclick="showConfigTab('compare')">Compare</div>
        <div class="tab" onclick="showConfigTab('push')">Push Config</div>
    </div>
    <div id="configTab-view" class="tab-content active">
        <div class="form-row">
            <div class="form-group"><label>Device</label><select id="cfgViewDevice" onchange=""></select></div>
        </div>
        <div class="btn-group" style="margin-top:0;margin-bottom:16px;">
            <button class="btn btn-primary" onclick="viewLiveConfig()">Get Live Config</button>
            <button class="btn btn-outline" onclick="backupConfig()">Backup Now</button>
        </div>
        <div id="cfgViewAlert" class="alert"></div>
        <div id="cfgViewContent" class="config-viewer" style="display:none;"></div>
    </div>
    <div id="configTab-backups" class="tab-content">
        <div class="form-group"><label>Device</label><select id="cfgBackupDevice" onchange="loadBackups()"></select></div>
        <div id="cfgBackupAlert" class="alert"></div>
        <table><thead><tr><th>Date</th><th>Type</th><th>Label</th><th>Hash</th><th>Actions</th></tr></thead><tbody id="backupTableBody"></tbody></table>
    </div>
    <div id="configTab-compare" class="tab-content">
        <div class="form-row">
            <div class="form-group"><label>Config A (Backup ID)</label><input type="number" id="cfgCompareA" placeholder="Backup ID"></div>
            <div class="form-group"><label>Config B (Backup ID or Device for live)</label><input type="number" id="cfgCompareB" placeholder="Backup ID"></div>
        </div>
        <div class="btn-group" style="margin-top:0;margin-bottom:16px;"><button class="btn btn-primary" onclick="compareConfigs()">Compare</button></div>
        <div id="cfgCompareAlert" class="alert"></div>
        <div id="cfgDiffContent" class="config-viewer" style="display:none;"></div>
    </div>
    <div id="configTab-push" class="tab-content">
        <div class="form-group"><label>Target Devices</label><div class="device-select" id="cfgPushDevices"></div></div>
        <div class="form-group"><label>Configuration Commands (set format, one per line)</label><textarea id="cfgPushCommands" rows="6" placeholder="set system ntp server 10.0.0.1&#10;set system name-server 10.0.0.2"></textarea></div>
        <div class="form-group"><label>Commit Comment</label><input type="text" id="cfgPushComment" placeholder="Pushed via Juniper Device Manager"></div>
        <div id="cfgPushAlert" class="alert"></div>
        <div class="btn-group"><button class="btn btn-danger" onclick="pushConfig()">Push Config (commit confirmed)</button></div>
    </div>
</div>

<!-- ====== USERS ====== -->
<div id="page-users" class="page">
    <div class="page-title">User Management</div>
    <div class="page-subtitle">Manage user accounts across multiple devices.</div>
    <div class="card">
        <div class="card-title">View Users on Device</div>
        <div class="form-row">
            <div class="form-group"><label>Device</label><select id="userViewDevice"></select></div>
        </div>
        <div class="btn-group" style="margin-top:0;margin-bottom:12px;"><button class="btn btn-outline" onclick="viewDeviceUsers()">List Users</button></div>
        <div id="userViewAlert" class="alert"></div>
        <table style="display:none;" id="userViewTable"><thead><tr><th>Username</th><th>Class</th></tr></thead><tbody id="userViewBody"></tbody></table>
    </div>
    <div class="card">
        <div class="card-title">Create User (Bulk)</div>
        <div id="userCreateAlert" class="alert"></div>
        <div class="form-group"><label>Target Devices</label><div class="device-select" id="userCreateDevices"></div></div>
        <div class="form-row">
            <div class="form-group"><label>Username</label><input type="text" id="userCreateName" placeholder="vc3admin" value="vc3admin"></div>
            <div class="form-group"><label>Class</label><select id="userCreateClass"><option value="super-user">super-user</option><option value="operator">operator</option><option value="read-only">read-only</option></select></div>
        </div>
        <div class="form-row">
            <div class="form-group"><label>Password</label><input type="password" id="userCreatePass1" placeholder="Min 6 characters"></div>
            <div class="form-group"><label>Confirm</label><input type="password" id="userCreatePass2" placeholder="Confirm password"></div>
        </div>
        <div class="btn-group"><button class="btn btn-success" onclick="bulkCreateUser()">Create User on Selected Devices</button></div>
    </div>
    <div class="card">
        <div class="card-title">Change Password (Bulk)</div>
        <div id="userPwAlert" class="alert"></div>
        <div class="form-group"><label>Target Devices</label><div class="device-select" id="userPwDevices"></div></div>
        <div class="form-row">
            <div class="form-group"><label>Username</label><input type="text" id="userPwName" placeholder="Username to change"></div>
        </div>
        <div class="form-row">
            <div class="form-group"><label>New Password</label><input type="password" id="userPwPass1" placeholder="New password"></div>
            <div class="form-group"><label>Confirm</label><input type="password" id="userPwPass2" placeholder="Confirm"></div>
        </div>
        <div class="btn-group"><button class="btn btn-primary" onclick="bulkChangePassword()">Change Password on Selected Devices</button></div>
    </div>
</div>

<!-- ====== FIRMWARE ====== -->
<div id="page-firmware" class="page">
    <div class="page-title">Firmware Management</div>
    <div class="page-subtitle">Track firmware versions and upgrade devices.</div>
    <div class="card">
        <div class="card-header"><div class="card-title" style="margin:0;">Version Matrix</div><button class="btn btn-outline" onclick="loadFirmwareMatrix()">Refresh</button></div>
        <table><thead><tr><th>Hostname</th><th>IP</th><th>Model</th><th>Current</th><th>Available</th><th>Status</th></tr></thead><tbody id="fwMatrixBody"><tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">Click Refresh to load.</td></tr></tbody></table>
    </div>
    <div class="card">
        <div class="card-header"><div class="card-title" style="margin:0;">Firmware Library</div><button class="btn btn-outline" onclick="showAddFirmware()">Register Image</button></div>
        <div id="addFwForm" style="display:none;margin-bottom:16px;">
            <div class="form-row">
                <div class="form-group"><label>File Path</label><input type="text" id="fwFilePath" placeholder="C:\firmware\junos-arm-32-21.4R3.tgz"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>Platform</label><input type="text" id="fwPlatform" placeholder="EX3400"></div>
                <div class="form-group"><label>Version</label><input type="text" id="fwVersion" placeholder="21.4R3-S7"></div>
            </div>
            <div id="fwAlert" class="alert"></div>
            <div class="btn-group" style="margin-top:8px;"><button class="btn btn-success" onclick="addFirmware()">Register</button><button class="btn btn-outline" onclick="hideAddFirmware()">Cancel</button></div>
        </div>
        <table><thead><tr><th>Filename</th><th>Platform</th><th>Version</th><th>Size</th><th>Actions</th></tr></thead><tbody id="fwLibBody"></tbody></table>
    </div>
</div>

<!-- ====== LOG ====== -->
<div id="page-log" class="page">
    <div class="page-title">Activity Log</div>
    <div class="page-subtitle">Session events and operation history.</div>
    <div class="card">
        <div class="card-header"><div class="card-title" style="margin:0;">Jobs</div><button class="btn btn-outline" onclick="loadJobs()">Refresh</button></div>
        <table><thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Started</th><th>Completed</th></tr></thead><tbody id="jobsBody"></tbody></table>
    </div>
    <div class="card" style="max-height:400px;overflow-y:auto;">
        <div class="card-title">Full Log</div>
        <div id="fullLogBody" style="font-family:var(--font-mono);font-size:12px;line-height:1.6;"></div>
    </div>
</div>

</div><!-- content-area -->

<!-- LOG PANEL -->
<div class="log-resize" id="logResize"></div>
<div class="log-panel">
    <div class="log-header"><span class="log-header-title">Console Log</span><button class="btn-sm" onclick="document.getElementById('logBody').innerHTML=''">Clear</button></div>
    <div class="log-body" id="logBody"></div>
</div>
</div>
</div>

<script>
// ---- STATE ----
var devices = [];
var lastLogCount = 0;

// ---- THEME ----
function initTheme(){var s=localStorage.getItem('jdm-theme')||'dark';document.documentElement.setAttribute('data-theme',s);}
function toggleTheme(){var c=document.documentElement.getAttribute('data-theme')||'dark';var n=c==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);localStorage.setItem('jdm-theme',n);}
initTheme();

// ---- API ----
function api(method,path,body){
    var opts={method:method,headers:{'Content-Type':'application/json'}};
    if(body)opts.body=JSON.stringify(body);
    return fetch(path,opts).then(function(r){return r.json();});
}

// ---- NAV ----
function showPage(page){
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active');});
    document.getElementById('page-'+page).classList.add('active');
    var nav=document.querySelector('.nav-item[data-page="'+page+'"]');
    if(nav)nav.classList.add('active');
    if(page==='dashboard')refreshDashboard();
    if(page==='setup'){loadSubnets();loadCreds();}
    if(page==='config')populateDeviceSelects();
    if(page==='users')populateDeviceSelects();
    if(page==='firmware'){loadFirmwareLibrary();loadFirmwareMatrix();}
    if(page==='log'){loadJobs();loadFullLog();}
}

// ---- ALERTS ----
function showAlert(id,type,msg){var el=document.getElementById(id);el.className='alert alert-'+type+' show';el.innerHTML=msg;}
function hideAlert(id){var el=document.getElementById(id);if(el){el.className='alert';el.innerHTML='';}}

function setLoading(btnOrId,loading){
    var btn=typeof btnOrId==='string'?document.getElementById(btnOrId):btnOrId;
    if(!btn)return;btn.disabled=loading;
    if(loading){btn.dataset.orig=btn.innerHTML;btn.innerHTML='<span class="spinner"></span> Working...';}
    else{btn.innerHTML=btn.dataset.orig||btn.innerHTML;}
}

// ---- AUTH ----
function checkAuth(){
    api('GET','/api/auth/status').then(function(data){
        if(!data.hasMasterPassword){
            document.getElementById('authTitle').textContent='Set Master Password';
            document.getElementById('authLabel').textContent='Choose a master password (min 8 chars)';
            document.getElementById('authConfirmGroup').style.display='';
            document.getElementById('btnAuth').textContent='Set Password';
            document.getElementById('lockOverlay').classList.add('show');
        } else if(!data.unlocked){
            document.getElementById('authTitle').textContent='Unlock Session';
            document.getElementById('authLabel').textContent='Master Password';
            document.getElementById('authConfirmGroup').style.display='none';
            document.getElementById('btnAuth').textContent='Unlock';
            document.getElementById('lockOverlay').classList.add('show');
        } else {
            document.getElementById('lockOverlay').classList.remove('show');
            updateLockBadge(true);
            refreshDashboard();
        }
    });
}

function doAuth(){
    hideAlert('authAlert');
    var pw=document.getElementById('authPassword').value;
    var isSetup=document.getElementById('authConfirmGroup').style.display!=='none';
    if(isSetup){
        var confirm=document.getElementById('authConfirm').value;
        if(pw!==confirm){showAlert('authAlert','danger','Passwords do not match.');return;}
        if(pw.length<8){showAlert('authAlert','danger','Password must be at least 8 characters.');return;}
        api('POST','/api/auth/setup',{password:pw}).then(function(data){
            if(data.success){document.getElementById('lockOverlay').classList.remove('show');updateLockBadge(true);refreshDashboard();}
            else showAlert('authAlert','danger',data.message);
        });
    } else {
        api('POST','/api/auth/unlock',{password:pw}).then(function(data){
            if(data.success){document.getElementById('lockOverlay').classList.remove('show');updateLockBadge(true);refreshDashboard();}
            else showAlert('authAlert','danger',data.message);
        });
    }
}

function doLock(){api('POST','/api/auth/lock').then(function(){updateLockBadge(false);checkAuth();});}

function updateLockBadge(unlocked){
    var b=document.getElementById('lockBadge');var t=document.getElementById('lockText');
    b.className='lock-badge '+(unlocked?'unlocked':'locked');
    t.textContent=unlocked?'Unlocked':'Locked';
    document.getElementById('btnLock').style.display=unlocked?'':'none';
}

// ---- DASHBOARD ----
function refreshDashboard(){
    api('GET','/api/devices').then(function(data){
        devices=data.devices||[];
        var online=0,offline=0,auth=0;
        devices.forEach(function(d){
            if(d.status==='online')online++;
            else if(d.status==='auth_failed')auth++;
            else if(d.status==='timeout'||d.status==='offline')offline++;
        });
        document.getElementById('statTotal').textContent=devices.length;
        document.getElementById('statOnline').textContent=online;
        document.getElementById('statOffline').textContent=offline;
        document.getElementById('statAuthFail').textContent=auth;
        document.getElementById('navDeviceCount').textContent=devices.length;
        renderDeviceTable();
    }).catch(function(){});
}

function renderDeviceTable(){
    var tbody=document.getElementById('deviceTableBody');
    if(!devices.length){tbody.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:40px;">No devices. Configure subnets in Setup, then Scan.</td></tr>';return;}
    var html='';
    devices.forEach(function(d){
        var sc='status-'+(d.status||'unknown');
        html+='<tr>';
        html+='<td style="font-weight:600;">'+(d.hostname||'--')+'</td>';
        html+='<td style="font-family:var(--font-mono);">'+d.host+'</td>';
        html+='<td>'+(d.model||'--')+'</td>';
        html+='<td style="font-family:var(--font-mono);">'+(d.firmware_version||'--')+'</td>';
        html+='<td>'+(d.serial_number||'--')+'</td>';
        html+='<td>'+(d.uptime||'--')+'</td>';
        html+='<td><span class="status-badge '+sc+'">'+(d.status||'unknown')+'</span></td>';
        html+='<td><button class="btn-sm" onclick="probeDevice('+d.id+')">Probe</button></td>';
        html+='</tr>';
    });
    tbody.innerHTML=html;
}

function probeDevice(id){
    api('POST','/api/devices/'+id+'/probe').then(function(data){
        if(data.success)refreshDashboard();
        else showAlert('dashAlert','danger',data.message);
    });
}

function runDiscovery(){
    api('POST','/api/discover',{}).then(function(data){
        if(data.success)showAlert('dashAlert','info',data.message+' Job ID: '+data.jobId);
        else showAlert('dashAlert','danger',data.message);
    });
}

// ---- SETUP: SUBNETS ----
function loadSubnets(){
    api('GET','/api/subnets').then(function(data){
        var tbody=document.getElementById('subnetTableBody');
        var subs=data.subnets||[];
        if(!subs.length){tbody.innerHTML='<tr><td colspan="3" style="color:var(--text-muted);">No subnets configured.</td></tr>';return;}
        var html='';subs.forEach(function(s){
            html+='<tr><td style="font-family:var(--font-mono);">'+s.cidr+'</td><td>'+s.label+'</td><td><button class="btn-sm" onclick="deleteSubnet('+s.id+')">Remove</button></td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function showAddSubnet(){document.getElementById('addSubnetForm').style.display='';}
function hideAddSubnet(){document.getElementById('addSubnetForm').style.display='none';}
function addSubnet(){
    var cidr=document.getElementById('newSubnetCidr').value.trim();
    var label=document.getElementById('newSubnetLabel').value.trim();
    if(!cidr){showAlert('subnetAlert','danger','Enter a CIDR.');return;}
    api('POST','/api/subnets',{cidr:cidr,label:label}).then(function(data){
        if(data.success){hideAddSubnet();loadSubnets();showAlert('subnetAlert','success',data.message);}
        else showAlert('subnetAlert','danger',data.message);
    });
}
function deleteSubnet(id){api('POST','/api/subnets/'+id+'/delete').then(function(){loadSubnets();});}

// ---- SETUP: CREDENTIALS ----
function loadCreds(){
    api('GET','/api/credentials').then(function(data){
        var tbody=document.getElementById('credTableBody');
        var creds=data.credentials||[];
        if(!creds.length){tbody.innerHTML='<tr><td colspan="4" style="color:var(--text-muted);">No credential groups.</td></tr>';return;}
        var html='';creds.forEach(function(c){
            html+='<tr><td style="font-weight:600;">'+c.name+'</td><td>'+c.username+'</td><td>'+c.port+'</td><td><button class="btn-sm" onclick="deleteCred('+c.id+')">Remove</button></td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function showAddCred(){document.getElementById('addCredForm').style.display='';}
function hideAddCred(){document.getElementById('addCredForm').style.display='none';}
function addCred(){
    var name=document.getElementById('newCredName').value.trim();
    var user=document.getElementById('newCredUser').value.trim();
    var pass=document.getElementById('newCredPass').value;
    var port=parseInt(document.getElementById('newCredPort').value)||830;
    if(!name||!user||!pass){showAlert('credAlert','danger','All fields required.');return;}
    api('POST','/api/credentials',{name:name,username:user,password:pass,port:port}).then(function(data){
        if(data.success){hideAddCred();loadCreds();showAlert('credAlert','success',data.message);}
        else showAlert('credAlert','danger',data.message);
    });
}
function deleteCred(id){api('POST','/api/credentials/'+id+'/delete').then(function(){loadCreds();});}

// ---- DEVICE SELECTS (populate dropdowns and checklists) ----
function populateDeviceSelects(){
    api('GET','/api/devices').then(function(data){
        devices=data.devices||[];
        // Single selects
        ['cfgViewDevice','cfgBackupDevice','userViewDevice'].forEach(function(id){
            var sel=document.getElementById(id);if(!sel)return;
            sel.innerHTML='<option value="">-- Select device --</option>';
            devices.forEach(function(d){
                var opt=document.createElement('option');opt.value=d.id;
                opt.textContent=(d.hostname||d.host)+' ('+d.host+')';sel.appendChild(opt);
            });
        });
        // Checkbox lists
        ['cfgPushDevices','userCreateDevices','userPwDevices'].forEach(function(id){
            var el=document.getElementById(id);if(!el)return;
            el.innerHTML='';
            devices.forEach(function(d){
                var lbl=document.createElement('label');
                lbl.innerHTML='<input type="checkbox" value="'+d.id+'"> '+(d.hostname||d.host)+' <span style="color:var(--text-muted);font-size:11px;">('+d.host+')</span>';
                el.appendChild(lbl);
            });
        });
    });
}
function getCheckedDeviceIds(containerId){
    var ids=[];
    document.querySelectorAll('#'+containerId+' input[type=checkbox]:checked').forEach(function(cb){ids.push(parseInt(cb.value));});
    return ids;
}

// ---- CONFIG ----
function showConfigTab(name){
    document.querySelectorAll('#page-config .tab').forEach(function(t){t.classList.remove('active');});
    document.querySelectorAll('#page-config .tab-content').forEach(function(t){t.classList.remove('active');});
    document.getElementById('configTab-'+name).classList.add('active');
    event.target.classList.add('active');
}
function viewLiveConfig(){
    var did=document.getElementById('cfgViewDevice').value;
    if(!did){showAlert('cfgViewAlert','danger','Select a device.');return;}
    hideAlert('cfgViewAlert');
    api('GET','/api/devices/'+did+'/config').then(function(data){
        if(data.success){document.getElementById('cfgViewContent').textContent=data.config;document.getElementById('cfgViewContent').style.display='';}
        else showAlert('cfgViewAlert','danger',data.message);
    });
}
function backupConfig(){
    var did=document.getElementById('cfgViewDevice').value;
    if(!did){showAlert('cfgViewAlert','danger','Select a device.');return;}
    api('POST','/api/devices/'+did+'/config/backup',{}).then(function(data){
        if(data.success)showAlert('cfgViewAlert','success',data.message);
        else showAlert('cfgViewAlert','danger',data.message);
    });
}
function loadBackups(){
    var did=document.getElementById('cfgBackupDevice').value;
    if(!did)return;
    api('GET','/api/devices/'+did+'/config/backups').then(function(data){
        var tbody=document.getElementById('backupTableBody');
        var bkps=data.backups||[];
        if(!bkps.length){tbody.innerHTML='<tr><td colspan="5" style="color:var(--text-muted);">No backups.</td></tr>';return;}
        var html='';bkps.forEach(function(b){
            html+='<tr><td>'+b.created_at+'</td><td>'+b.backup_type+'</td><td>'+(b.label||'--')+'</td><td style="font-family:var(--font-mono);font-size:11px;">'+b.config_hash.substring(0,12)+'</td>';
            html+='<td><button class="btn-sm" onclick="viewBackup('+b.id+')">View</button></td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function viewBackup(id){
    api('GET','/api/config/backups/'+id).then(function(data){
        if(data.backup){document.getElementById('cfgViewContent').textContent=data.backup.config_text;document.getElementById('cfgViewContent').style.display='';showConfigTab('view');}
    });
}
function compareConfigs(){
    var a=document.getElementById('cfgCompareA').value;
    var b=document.getElementById('cfgCompareB').value;
    if(!a){showAlert('cfgCompareAlert','danger','Enter at least Backup ID A.');return;}
    api('POST','/api/config/compare',{backup_id_a:parseInt(a),backup_id_b:b?parseInt(b):null}).then(function(data){
        if(data.success){
            var el=document.getElementById('cfgDiffContent');
            el.style.display='';
            // Colorize diff
            var lines=data.diff.split('\n').map(function(l){
                if(l.startsWith('+++') || l.startsWith('---') || l.startsWith('@@'))return '<span class="diff-hdr">'+esc(l)+'</span>';
                if(l.startsWith('+'))return '<span class="diff-add">'+esc(l)+'</span>';
                if(l.startsWith('-'))return '<span class="diff-del">'+esc(l)+'</span>';
                return esc(l);
            });
            el.innerHTML=lines.join('\n');
        } else showAlert('cfgCompareAlert','danger',data.message);
    });
}
function pushConfig(){
    var ids=getCheckedDeviceIds('cfgPushDevices');
    var cmds=document.getElementById('cfgPushCommands').value.trim();
    var comment=document.getElementById('cfgPushComment').value.trim()||'Pushed via Juniper Device Manager';
    if(!ids.length){showAlert('cfgPushAlert','danger','Select at least one device.');return;}
    if(!cmds){showAlert('cfgPushAlert','danger','Enter config commands.');return;}
    if(!confirm('Push config to '+ids.length+' device(s) using commit confirmed?'))return;
    api('POST','/api/config/push',{device_ids:ids,commands:cmds,comment:comment}).then(function(data){
        if(data.success){
            var msg='Results: ';
            for(var k in data.results){msg+=k+': '+(data.results[k].success?'OK':'FAIL')+' ';}
            showAlert('cfgPushAlert','info',msg);
        } else showAlert('cfgPushAlert','danger',data.message);
    });
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// ---- USERS ----
function viewDeviceUsers(){
    var did=document.getElementById('userViewDevice').value;
    if(!did){showAlert('userViewAlert','danger','Select a device.');return;}
    api('GET','/api/devices/'+did+'/users').then(function(data){
        if(data.success){
            document.getElementById('userViewTable').style.display='';
            var tbody=document.getElementById('userViewBody');
            var html='';(data.users||[]).forEach(function(u){html+='<tr><td style="font-weight:600;">'+u.username+'</td><td>'+u['class']+'</td></tr>';});
            tbody.innerHTML=html||'<tr><td colspan="2">No users found.</td></tr>';
        } else showAlert('userViewAlert','danger',data.message);
    });
}
function bulkCreateUser(){
    var ids=getCheckedDeviceIds('userCreateDevices');
    var username=document.getElementById('userCreateName').value.trim();
    var p1=document.getElementById('userCreatePass1').value;
    var p2=document.getElementById('userCreatePass2').value;
    var cls=document.getElementById('userCreateClass').value;
    if(!ids.length){showAlert('userCreateAlert','danger','Select at least one device.');return;}
    if(!username){showAlert('userCreateAlert','danger','Enter a username.');return;}
    if(p1.length<6){showAlert('userCreateAlert','danger','Password must be at least 6 characters.');return;}
    if(p1!==p2){showAlert('userCreateAlert','danger','Passwords do not match.');return;}
    if(!confirm('Create user "'+username+'" on '+ids.length+' device(s)?'))return;
    api('POST','/api/users/create',{device_ids:ids,username:username,password:p1,userClass:cls}).then(function(data){
        if(data.success){
            var msg='Results: ';for(var k in data.results){msg+=k+':'+(data.results[k].success?'OK':'data.results[k].message')+' ';}
            showAlert('userCreateAlert','info',msg);
        } else showAlert('userCreateAlert','danger',data.message);
    });
}
function bulkChangePassword(){
    var ids=getCheckedDeviceIds('userPwDevices');
    var username=document.getElementById('userPwName').value.trim();
    var p1=document.getElementById('userPwPass1').value;
    var p2=document.getElementById('userPwPass2').value;
    if(!ids.length){showAlert('userPwAlert','danger','Select at least one device.');return;}
    if(!username){showAlert('userPwAlert','danger','Enter a username.');return;}
    if(p1.length<6){showAlert('userPwAlert','danger','Password must be at least 6 characters.');return;}
    if(p1!==p2){showAlert('userPwAlert','danger','Passwords do not match.');return;}
    if(!confirm('Change password for "'+username+'" on '+ids.length+' device(s)?'))return;
    api('POST','/api/users/change-password',{device_ids:ids,username:username,password:p1}).then(function(data){
        if(data.success)showAlert('userPwAlert','success','Password change submitted.');
        else showAlert('userPwAlert','danger',data.message);
    });
}

// ---- FIRMWARE ----
function loadFirmwareMatrix(){
    api('GET','/api/firmware/matrix').then(function(data){
        var tbody=document.getElementById('fwMatrixBody');
        var m=data.matrix||[];
        if(!m.length){tbody.innerHTML='<tr><td colspan="6" style="color:var(--text-muted);">No devices.</td></tr>';return;}
        var html='';m.forEach(function(r){
            var upgrade=r.needs_upgrade?'<span class="status-badge status-auth_failed">Upgrade Available</span>':'<span class="status-badge status-online">Current</span>';
            html+='<tr><td>'+r.hostname+'</td><td>'+r.host+'</td><td>'+r.model+'</td><td style="font-family:var(--font-mono);">'+r.current_version+'</td><td style="font-family:var(--font-mono);">'+(r.available_version||'--')+'</td><td>'+upgrade+'</td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function loadFirmwareLibrary(){
    api('GET','/api/firmware/images').then(function(data){
        var tbody=document.getElementById('fwLibBody');
        var imgs=data.images||[];
        if(!imgs.length){tbody.innerHTML='<tr><td colspan="5" style="color:var(--text-muted);">No firmware registered.</td></tr>';return;}
        var html='';imgs.forEach(function(i){
            var size=i.file_size?(Math.round(i.file_size/1048576)+'MB'):'--';
            html+='<tr><td>'+i.filename+'</td><td>'+i.platform+'</td><td style="font-family:var(--font-mono);">'+i.version+'</td><td>'+size+'</td><td><button class="btn-sm" onclick="deleteFirmware('+i.id+')">Remove</button></td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function showAddFirmware(){document.getElementById('addFwForm').style.display='';}
function hideAddFirmware(){document.getElementById('addFwForm').style.display='none';}
function addFirmware(){
    var fp=document.getElementById('fwFilePath').value.trim();
    var plat=document.getElementById('fwPlatform').value.trim();
    var ver=document.getElementById('fwVersion').value.trim();
    if(!fp||!plat||!ver){showAlert('fwAlert','danger','All fields required.');return;}
    api('POST','/api/firmware/images',{filepath:fp,platform:plat,version:ver}).then(function(data){
        if(data.success){hideAddFirmware();loadFirmwareLibrary();showAlert('fwAlert','success',data.message);}
        else showAlert('fwAlert','danger',data.message);
    });
}
function deleteFirmware(id){api('POST','/api/firmware/images/'+id+'/delete').then(function(){loadFirmwareLibrary();});}

// ---- JOBS / LOG ----
function loadJobs(){
    api('GET','/api/jobs').then(function(data){
        var tbody=document.getElementById('jobsBody');
        var jobs=data.jobs||[];
        if(!jobs.length){tbody.innerHTML='<tr><td colspan="5" style="color:var(--text-muted);">No jobs.</td></tr>';return;}
        var html='';jobs.forEach(function(j){
            var sc='status-'+(j.status==='completed'?'online':j.status==='running'?'auth_failed':'offline');
            html+='<tr><td>'+j.id+'</td><td>'+j.job_type+'</td><td><span class="status-badge '+sc+'">'+j.status+'</span></td><td>'+(j.started_at||'--')+'</td><td>'+(j.completed_at||'--')+'</td></tr>';
        });
        tbody.innerHTML=html;
    });
}
function loadFullLog(){
    api('GET','/api/log').then(function(data){
        var el=document.getElementById('fullLogBody');
        var html='';(data.entries||[]).forEach(function(e){
            html+='<div class="log-entry '+e.level+'">['+e.level+'] '+e.time+'  '+e.message+'</div>';
        });
        el.innerHTML=html;
    });
}

// ---- LOG PANEL POLL ----
function pollLog(){
    api('GET','/api/log').then(function(data){
        if(!data.entries)return;
        var body=document.getElementById('logBody');
        if(data.entries.length>lastLogCount){
            data.entries.slice(lastLogCount).forEach(function(e){
                var div=document.createElement('div');div.className='log-entry '+e.level;
                div.textContent='['+e.level+'] '+e.time+'  '+e.message;body.appendChild(div);
            });
            lastLogCount=data.entries.length;body.scrollTop=body.scrollHeight;
        }
    }).catch(function(){});
}
setInterval(pollLog,2000);

// ---- LOG RESIZE ----
(function(){var r=document.getElementById('logResize'),p=r.nextElementSibling,sy,sh;
r.addEventListener('mousedown',function(e){sy=e.clientY;sh=p.offsetHeight;document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);e.preventDefault();});
function mv(e){p.style.height=Math.max(60,sh-(e.clientY-sy))+'px';}
function up(){document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);}
})();

// ---- SHUTDOWN ----
function doShutdown(){
    if(!confirm('Shut down the server?'))return;
    api('POST','/api/shutdown').then(function(){
        document.body.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center;color:var(--text-muted);"><h2>Server Stopped</h2><p>Close this tab.</p></div></div>';
    });
}

// ---- INIT ----
checkAuth();
setInterval(function(){if(document.querySelector('#page-dashboard.active'))refreshDashboard();},30000);
</script>
</body>
</html>'''
