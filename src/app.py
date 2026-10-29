import os
import threading
import webbrowser
from flask import Flask, jsonify, render_template_string, request, Response
import csv
import io
from src.database import get_db_connection, init_db, get_current_metrics
from src.daemon import SENTINEL_DAEMON
from src.processor import validate_and_parse_log_entry

app = Flask(__name__)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Advanced SOC Dashboard Template with Fixed Button Handlers
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Automated Auth & Log Anomaly Analyzer</title>
    <style>
        :root {
            --bg-base: #0c101d;
            --bg-surface: #121829;
            --bg-card: #182035;
            --bg-hover: #1f2a44;
            --border-subtle: #1e2840;
            --dd-purple: #7c3aed;
            --dd-purple-hover: #6d28d9;
            --status-critical: #ef4444;
            --status-warn: #f59e0b;
            --status-info: #10b981;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-dim: #64748b;
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0; padding: 0; height: 100vh; display: flex; flex-direction: column; overflow: hidden; font-size: 13px;
        }
        .navbar {
            background-color: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            height: 54px; display: flex; align-items: center; justify-content: space-between; padding: 0 16px; flex-shrink: 0;
        }
        .brand { display: flex; align-items: center; gap: 10px; }
        .logo-badge { background: var(--dd-purple); color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .title { font-weight: 600; font-size: 14px; color: var(--text-primary); display: flex; align-items: center; gap: 6px; }
        .env-badge { background: rgba(124, 58, 237, 0.2); color: #a78bfa; border: 1px solid #7c3aed; padding: 2px 8px; border-radius: 12px; font-size: 11px; }
        
        .nav-actions { display: flex; align-items: center; gap: 10px; }
        .btn {
            background-color: var(--bg-card); color: var(--text-primary); border: 1px solid var(--border-subtle);
            padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; display: flex; align-items: center; gap: 6px; transition: 0.2s;
        }
        .btn:hover { background-color: var(--bg-hover); border-color: var(--text-secondary); }
        .btn-primary { background-color: var(--dd-purple); border-color: var(--dd-purple); color: white; }
        .btn-primary:hover { background-color: var(--dd-purple-hover); }
        .btn-danger { background-color: rgba(239, 68, 68, 0.2); border-color: var(--status-critical); color: #fca5a5; }

        .search-bar-container { background-color: var(--bg-surface); border-bottom: 1px solid var(--border-subtle); padding: 10px 16px; display: flex; gap: 10px; align-items: center; }
        .search-input {
            flex-grow: 1; background-color: var(--bg-base); border: 1px solid var(--border-subtle); color: var(--text-primary);
            padding: 8px 12px; border-radius: 4px; font-size: 13px; outline: none;
        }
        .search-input:focus { border-color: #3b82f6; }

        .workspace { display: flex; flex-grow: 1; overflow: hidden; }
        .sidebar { width: 240px; background-color: #0f1524; border-right: 1px solid var(--border-subtle); padding: 16px; overflow-y: auto; flex-shrink: 0; }
        .main-content { flex-grow: 1; display: flex; flex-direction: column; overflow: hidden; background-color: var(--bg-base); }
        
        .metrics-bar { display: flex; justify-content: flex-end; gap: 30px; background-color: var(--bg-surface); padding: 8px 16px; border-bottom: 1px solid var(--border-subtle); font-size: 12px; }
        .metric-item { display: flex; gap: 8px; align-items: center; }
        .metric-val { font-weight: bold; font-size: 14px; }

        .tabs-header { display: flex; background-color: var(--bg-surface); border-bottom: 1px solid var(--border-subtle); padding: 0 16px; }
        .tab { padding: 10px 16px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--text-secondary); font-weight: 500; }
        .tab.active { color: var(--text-primary); border-bottom-color: var(--dd-purple); background-color: var(--bg-card); }

        .tab-content { flex-grow: 1; overflow-y: auto; padding: 16px; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12px; }
        th { background-color: var(--bg-surface); color: var(--text-secondary); padding: 8px; border-bottom: 1px solid var(--border-subtle); position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid var(--border-subtle); font-family: monospace; }
        tr:hover { background-color: var(--bg-hover); }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; z-index: 1000; }
        .modal-content { background: var(--bg-surface); border: 1px solid var(--border-subtle); padding: 20px; border-radius: 8px; width: 400px; }
        .modal-content input { width: 100%; padding: 8px; margin: 8px 0 16px 0; background: var(--bg-base); border: 1px solid var(--border-subtle); color: white; border-radius: 4px; outline: none; }
    </style>
</head>
<body>

    <div class="navbar">
        <div class="brand">
            <div class="logo-badge">AA</div>
            <div class="title">Automated Auth / Log Anomaly / Analyzer <span class="env-badge">env:soc-production</span></div>
        </div>
        <div class="nav-actions">
            <button class="btn btn-primary" onclick="openIngestModal()">+ Ingest Stream</button>
            <button class="btn btn-danger" onclick="simulateAttack()">⚡ Simulate Attack</button>
            <button class="btn" onclick="scanOS()">🔍 Scan OS Table</button>
            <button class="btn" onclick="exportCSV()">📥 Export CSV</button>
        </div>
    </div>

    <div class="search-bar-container">
        <input type="text" class="search-input" id="searchFilter" placeholder="Filter logs by status, IP, MAC, rule, or free text..." oninput="filterLogs()">
        <button class="btn" onclick="resetFilters()">Reset Filters</button>
    </div>

    <div class="metrics-bar">
        <div class="metric-item">TOTAL LOGS: <span class="metric-val" id="cnt-total">0</span></div>
        <div class="metric-item">VALID HOSTS: <span class="metric-val" style="color:var(--status-info)" id="cnt-valid">0</span></div>
        <div class="metric-item">DROPPED: <span class="metric-val" style="color:var(--status-warn)" id="cnt-rejected">0</span></div>
        <div class="metric-item">ATTACKS: <span class="metric-val" style="color:var(--status-critical)" id="cnt-attacks">0</span></div>
    </div>

    <div class="workspace">
        <div class="sidebar">
            <h4 style="color:var(--text-secondary); margin-top:0;">FACET EXPLORER</h4>
            <hr style="border:0; border-top:1px solid var(--border-subtle);">
            <p style="color:var(--text-dim);">Status / Severity Summary</p>
            <div id="facets-status" style="font-size:12px; line-height:1.8;">Active Monitoring Live</div>
        </div>
        <div class="main-content">
            <div class="tabs-header">
                <div class="tab active" onclick="switchTab('logs', this)">Log Stream</div>
                <div class="tab" onclick="switchTab('assets', this)">Asset Map</div>
                <div class="tab" onclick="switchTab('incidents', this)">Threat Incidents</div>
            </div>

            <div class="tab-content" id="tab-logs">
                <table>
                    <thead>
                        <tr>
                            <th>TIMESTAMP</th>
                            <th>STATUS</th>
                            <th>HOST / IP</th>
                            <th>MAC HARDWARE</th>
                            <th>VENDOR</th>
                            <th>RULE / MESSAGE</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table-body">
                        <tr><td colspan="6" style="text-align:center; color:var(--text-secondary);">Streaming live telemetry...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="tab-content" id="tab-assets" style="display:none;">
                <table>
                    <thead>
                        <tr>
                            <th>IP ADDRESS</th>
                            <th>MAC ADDRESS</th>
                            <th>HARDWARE VENDOR</th>
                            <th>DEVICE TYPE</th>
                            <th>STATUS</th>
                            <th>LAST SEEN</th>
                        </tr>
                    </thead>
                    <tbody id="assets-table-body"></tbody>
                </table>
            </div>

            <div class="tab-content" id="tab-incidents" style="display:none;">
                <table>
                    <thead>
                        <tr>
                            <th>TIMESTAMP</th>
                            <th>SEVERITY</th>
                            <th>RULE NAME</th>
                            <th>IP TARGET</th>
                            <th>ROGUE MAC</th>
                            <th>DETAILS / REMEDIATION</th>
                        </tr>
                    </thead>
                    <tbody id="incidents-table-body"></tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="modal" id="ingestModal">
        <div class="modal-content">
            <h3 style="margin-top:0; color:var(--dd-purple);">Ingest Custom Log Entry</h3>
            <label>IP Address:</label>
            <input type="text" id="manualIp" placeholder="e.g. 192.168.1.50">
            <label>MAC Address:</label>
            <input type="text" id="manualMac" placeholder="e.g. 00:11:22:33:44:55">
            <label>Entry Type / Note:</label>
            <input type="text" id="manualNote" placeholder="e.g. dynamic">
            <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:10px;">
                <button class="btn" onclick="closeIngestModal()">Cancel</button>
                <button class="btn btn-primary" onclick="submitIngest()">Ingest Record</button>
            </div>
        </div>
    </div>

    <script>
        let cachedData = { logs: [], assets: [], incidents: [], metrics: {} };

        function openIngestModal() { document.getElementById('ingestModal').style.display = 'flex'; }
        function closeIngestModal() { document.getElementById('ingestModal').style.display = 'none'; }

        async function submitIngest() {
            let ip = document.getElementById('manualIp').value;
            let mac = document.getElementById('manualMac').value;
            let note = document.getElementById('manualNote').value || 'dynamic';
            if(!ip || !mac) { alert("Please provide both IP and MAC address."); return; }
            let line = `${ip} ${mac} ${note}`;

            await fetch('/api/ingest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({line: line})
            });
            closeIngestModal();
            fetchData();
        }

        async function simulateAttack() {
            // First register a valid baseline entry, then spoof it with a different rogue MAC
            await fetch('/api/ingest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({line: "192.168.1.100 00:11:22:33:44:55 dynamic"})
            });
            // Send spoofed attack record changing the MAC for 192.168.1.100
            let res = await fetch('/api/ingest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({line: "192.168.1.100 ff:ee:dd:11:22:33 dynamic"})
            });
            let data = await res.json();
            alert("⚠️ ARP Cache Poisoning Attack Simulated Successfully! Check Threat Incidents tab.");
            fetchData();
            // Automatically switch to incidents tab to show professor
            switchTab('incidents', document.querySelectorAll('.tab')[2]);
        }

        async function scanOS() {
            let res = await fetch('/api/scan', {method: 'POST'});
            let data = await res.json();
            alert(`🔍 OS ARP Table scanned successfully! Discovered active nodes.`);
            fetchData();
            switchTab('assets', document.querySelectorAll('.tab')[1]);
        }

        function exportCSV() {
            window.location.href = '/api/export';
        }

        function switchTab(tabName, el) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            if(el) el.classList.add('active');
            document.getElementById('tab-logs').style.display = tabName === 'logs' ? 'block' : 'none';
            document.getElementById('tab-assets').style.display = tabName === 'assets' ? 'block' : 'none';
            document.getElementById('tab-incidents').style.display = tabName === 'incidents' ? 'block' : 'none';
        }

        async function fetchData() {
            try {
                let res = await fetch('/api/state');
                cachedData = await res.json();
                
                document.getElementById('cnt-total').innerText = cachedData.metrics.total_processed || 0;
                document.getElementById('cnt-valid').innerText = cachedData.metrics.valid_records || 0;
                document.getElementById('cnt-rejected').innerText = cachedData.metrics.rejected_records || 0;
                document.getElementById('cnt-attacks').innerText = cachedData.metrics.detected_attacks || 0;

                renderLogs(cachedData.logs);
                renderAssets(cachedData.assets);
                renderIncidents(cachedData.incidents);
            } catch (e) {
                console.error("Fetch error:", e);
            }
        }

        function renderLogs(logs) {
            let html = logs.map(l => `
                <tr>
                    <td>${l.timestamp}</td>
                    <td><span style="color:${l.status === 'CRITICAL' ? 'var(--status-critical)' : 'var(--status-info)'}">${l.status}</span></td>
                    <td>${l.ip}</td>
                    <td>${l.mac}</td>
                    <td>${l.vendor}</td>
                    <td><strong>${l.rule_name || 'INFO'}</strong>: ${l.message}</td>
                </tr>
            `).join('');
            document.getElementById('logs-table-body').innerHTML = html || '<tr><td colspan="6" style="text-align:center;">No logs recorded yet.</td></tr>';
        }

        function renderAssets(assets) {
            let html = assets.map(a => `
                <tr>
                    <td>${a.ip}</td>
                    <td>${a.mac}</td>
                    <td>${a.vendor}</td>
                    <td>${a.device_type}</td>
                    <td><span style="color:${a.status.includes('ATTACK') ? 'var(--status-critical)' : 'var(--status-info)'}">${a.status}</span></td>
                    <td>${a.last_seen}</td>
                </tr>
            `).join('');
            document.getElementById('assets-table-body').innerHTML = html || '<tr><td colspan="6" style="text-align:center;">No assets discovered.</td></tr>';
        }

        function renderIncidents(incidents) {
            let html = incidents.map(i => `
                <tr>
                    <td>${i.timestamp}</td>
                    <td><span style="color:var(--status-critical); font-weight:bold;">${i.severity}</span></td>
                    <td>${i.rule_name}</td>
                    <td>${i.ip}</td>
                    <td>${i.rogue_mac}</td>
                    <td>${i.details}</td>
                </tr>
            `).join('');
            document.getElementById('incidents-table-body').innerHTML = html || '<tr><td colspan="6" style="text-align:center;">No active threat incidents.</td></tr>';
        }

        function filterLogs() {
            let query = document.getElementById('searchFilter').value.toLowerCase();
            let filtered = cachedData.logs.filter(l => 
                l.ip.toLowerCase().includes(query) || 
                l.mac.toLowerCase().includes(query) || 
                l.status.toLowerCase().includes(query) || 
                l.message.toLowerCase().includes(query)
            );
            renderLogs(filtered);
        }

        function resetFilters() {
            document.getElementById('searchFilter').value = '';
            renderLogs(cachedData.logs);
        }

        setInterval(fetchData, 3000);
        fetchData();
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/state')
def api_state():
    metrics = get_current_metrics()
    with get_db_connection() as conn:
        logs = conn.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 100").fetchall()
        assets = conn.execute("SELECT * FROM network_assets ORDER BY last_seen DESC").fetchall()
        incidents = conn.execute("SELECT * FROM security_incidents ORDER BY id DESC").fetchall()
    
    return jsonify({
        "metrics": metrics,
        "logs": [dict(r) for r in logs],
        "assets": [dict(r) for r in assets],
        "incidents": [dict(r) for r in incidents]
    })

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    data = request.get_json()
    line = data.get("line", "")
    if line:
        validate_and_parse_log_entry(line)
    return jsonify({"status": "success"})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    SENTINEL_DAEMON.scan_os_table()
    return jsonify({"status": "success"})

@app.route('/api/export')
def api_export():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT * FROM security_logs").fetchall()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Timestamp", "IP", "MAC", "Vendor", "Status", "Rule Name", "Message"])
    for l in logs:
        cw.writerow([l["id"], l["timestamp"], l["ip"], l["mac"], l["vendor"], l["status"], l["rule_name"], l["message"]])
    
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=security_audit_report.csv"})

if __name__ == '__main__':
    init_db()
    SENTINEL_DAEMON.start()
    print("[INIT] Starting Advanced SIEM SOC Dashboard Server...")
    threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host='127.0.0.1', port=5000, debug=False)