// Client-Side Simulated Scenarios (Fallback for GitHub Pages / Static Hosting)
const CLIENT_SCENARIOS = {
    "ssh_brute_force": {
        "title": "SSH Brute Force Attack",
        "description": "Multiple failed SSH login attempts from a single IP, followed by a successful login.",
        "logs": [
            {
                "timestamp": "2026-06-25T11:00:01Z",
                "source": "wazuh",
                "agent": {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
                "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"},
                "data": {"srcip": "198.51.100.42", "dstuser": "admin", "port": "43922"}
            },
            {
                "timestamp": "2026-06-25T11:00:05Z",
                "source": "wazuh",
                "agent": {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
                "rule": {"id": "5712", "level": 5, "description": "sshd: Authentication failed"},
                "data": {"srcip": "198.51.100.42", "dstuser": "root", "port": "43930"}
            },
            {
                "timestamp": "2026-06-25T11:00:10Z",
                "source": "wazuh",
                "agent": {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
                "rule": {"id": "5712", "level": 5, "description": "sshd: Authentication failed"},
                "data": {"srcip": "198.51.100.42", "dstuser": "root", "port": "43934"}
            },
            {
                "timestamp": "2026-06-25T11:00:15Z",
                "source": "wazuh",
                "agent": {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
                "rule": {"id": "5715", "level": 10, "description": "sshd: Authentication success"},
                "data": {"srcip": "198.51.100.42", "dstuser": "ubuntu", "port": "43940"}
            },
            {
                "timestamp": "2026-06-25T11:00:20Z",
                "source": "syslog",
                "agent": {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
                "rule": {"id": "1002", "level": 7, "description": "User ubuntu executed command with sudo"},
                "data": {"command": "/bin/bash", "working_dir": "/home/ubuntu", "user": "ubuntu"}
            }
        ]
    },
    "sql_injection": {
        "title": "SQL Injection & Data Leakage",
        "description": "Exploitation of web app parameter leading to SQL error logs and heavy outbound traffic.",
        "logs": [
            {
                "timestamp": "2026-06-25T11:05:00Z",
                "source": "nginx-access",
                "agent": {"id": "002", "name": "nginx-ingress", "ip": "10.0.0.10"},
                "rule": {"id": "100201", "level": 6, "description": "Nginx: GET request contains SQL injection patterns"},
                "data": {"srcip": "203.0.113.15", "request": "GET /api/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "status": 200, "bytes_sent": 4096}
            },
            {
                "timestamp": "2026-06-25T11:05:02Z",
                "source": "mysql-error",
                "agent": {"id": "003", "name": "db-server-01", "ip": "10.0.0.20"},
                "rule": {"id": "200101", "level": 8, "description": "MySQL: Query error or syntax failure from web application backend"},
                "data": {"query": "SELECT * FROM products WHERE id=1 UNION SELECT username,password FROM users", "error": "Table 'users' accessed by db_user without adequate permissions"}
            },
            {
                "timestamp": "2026-06-25T11:05:10Z",
                "source": "nginx-access",
                "agent": {"id": "002", "name": "nginx-ingress", "ip": "10.0.0.10"},
                "rule": {"id": "100202", "level": 11, "description": "Nginx: Unusual large payload outbound sent to single client IP"},
                "data": {"srcip": "203.0.113.15", "request": "GET /api/products?id=1%20UNION%20SELECT%20null,load_file('/etc/passwd')", "status": 200, "bytes_sent": 1048576}
            }
        ]
    },
    "ransomware": {
        "title": "Ransomware Encryption",
        "description": "Fast file modifications, renaming actions, and creation of ransom notes on a file server.",
        "logs": [
            {
                "timestamp": "2026-06-25T11:10:00Z",
                "source": "sysmon",
                "agent": {"id": "005", "name": "corp-fileserver", "ip": "10.10.1.15"},
                "rule": {"id": "92201", "level": 9, "description": "Sysmon: High rate of file modification events"},
                "data": {"process": "C:\\Users\\admin\\Downloads\\invoice.exe", "file_name": "Q3_Report.docx.locked", "action": "FileWrite"}
            },
            {
                "timestamp": "2026-06-25T11:10:01Z",
                "source": "sysmon",
                "agent": {"id": "005", "name": "corp-fileserver", "ip": "10.10.1.15"},
                "rule": {"id": "92201", "level": 9, "description": "Sysmon: High rate of file modification events"},
                "data": {"process": "C:\\Users\\admin\\Downloads\\invoice.exe", "file_name": "CustomerList.xlsx.locked", "action": "FileWrite"}
            },
            {
                "timestamp": "2026-06-25T11:10:02Z",
                "source": "sysmon",
                "agent": {"id": "005", "name": "corp-fileserver", "ip": "10.10.1.15"},
                "rule": {"id": "92202", "level": 12, "description": "Sysmon: Creation of file with typical ransom note extension"},
                "data": {"process": "C:\\Users\\admin\\Downloads\\invoice.exe", "file_name": "RESTORE_FILES_README.txt", "action": "FileCreate"}
            },
            {
                "timestamp": "2026-06-25T11:10:05Z",
                "source": "wazuh",
                "agent": {"id": "005", "name": "corp-fileserver", "ip": "10.10.1.15"},
                "rule": {"id": "60112", "level": 13, "description": "Active response: Shadow copies deletion command detected"},
                "data": {"command": "vssadmin.exe delete shadows /all /quiet", "user": "SYSTEM"}
            }
        ]
    },
    "c2_beaconing": {
        "title": "Cobalt Strike C2 Beaconing",
        "description": "Internal workstation making regular HTTP connections to an unclassified external IP at precise intervals.",
        "logs": [
            {
                "timestamp": "2026-06-25T11:15:00Z",
                "source": "zeek-conn",
                "agent": {"id": "010", "name": "core-switch", "ip": "10.10.2.1"},
                "rule": {"id": "80211", "level": 7, "description": "Zeek: Repetitive connections to external host"},
                "data": {"srcip": "10.10.2.85", "dstip": "45.33.22.11", "dstport": 443, "interval": "10s", "bytes_sent": 512}
            },
            {
                "timestamp": "2026-06-25T11:15:10Z",
                "source": "zeek-conn",
                "agent": {"id": "010", "name": "core-switch", "ip": "10.10.2.1"},
                "rule": {"id": "80211", "level": 7, "description": "Zeek: Repetitive connections to external host"},
                "data": {"srcip": "10.10.2.85", "dstip": "45.33.22.11", "dstport": 443, "interval": "10s", "bytes_sent": 520}
            },
            {
                "timestamp": "2026-06-25T11:15:20Z",
                "source": "zeek-conn",
                "agent": {"id": "010", "name": "core-switch", "ip": "10.10.2.1"},
                "rule": {"id": "80212", "level": 9, "description": "Zeek: SSL certificate mismatch or self-signed cert on port 443"},
                "data": {"srcip": "10.10.2.85", "dstip": "45.33.22.11", "subject": "CN=attacker.c2domain.net"}
            }
        ]
    }
};

const MITRE_LOOKUP = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts.",
        "mitigation": "Account lockout policies, multi-factor authentication (MFA), monitoring login failures."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or system.",
        "mitigation": "Web application firewalls (WAF), input validation, regular software patching."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "mitigation": "Restrict execution of scripts, enable logging of command line parameters, script signing."
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability of system and network resources.",
        "mitigation": "Regular offline backups, strict user privileges, application whitelisting, Endpoint Detection and Response (EDR)."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to evade detection and blend in with network traffic.",
        "mitigation": "Network intrusion detection/prevention systems (IDS/IPS), SSL/TLS decryption and inspection."
    }
};

// State Management
let state = {
    scenarios: [],
    selectedScenario: null,
    activeContext: null,
    liveStreamInterval: null,
    streamLogsCache: [],
    isOffline: false,
    config: {
        provider: "ollama",
        model: "llama3",
        api_key: ""
    }
};

// DOM Elements
const ollamaPill = document.getElementById("ollama-status-pill");
const scenariosList = document.getElementById("scenarios-list");
const customLogsInput = document.getElementById("custom-logs");
const btnAnalyzeCustom = document.getElementById("btn-analyze-custom");
const btnClear = document.getElementById("btn-clear");
const btnStream = document.getElementById("btn-stream");
const logTerminal = document.getElementById("log-terminal");

const loadingOverlay = document.getElementById("loading-overlay");
const insightsEmpty = document.querySelector(".middle-panel .empty-state");
const insightsWrapper = document.getElementById("insights-wrapper");
const threatPriority = document.getElementById("threat-priority");
const threatConfidence = document.getElementById("threat-confidence");
const threatName = document.getElementById("threat-name");
const threatHeader = document.getElementById("threat-header");
const mitreTactic = document.getElementById("mitre-tactic");
const mitreTechnique = document.getElementById("mitre-technique");
const mitreDescription = document.getElementById("mitre-description");
const threatExplanation = document.getElementById("threat-explanation");
const timelineList = document.getElementById("timeline-list");

const remediationEmpty = document.getElementById("remediation-empty");
const remediationWrapper = document.getElementById("remediation-wrapper");
const remediationText = document.getElementById("remediation-text");
const btnRunPlaybook = document.getElementById("btn-run-playbook");
const containmentStatus = document.getElementById("containment-status");

const chatMessages = document.getElementById("chat-messages");
const chatInput = document.getElementById("chat-input");
const btnChatSend = document.getElementById("btn-chat-send");

const settingsModal = document.getElementById("settings-modal");
const settingsTrigger = document.getElementById("settings-trigger");
const modalClose = document.getElementById("modal-close");
const providerSelect = document.getElementById("provider-select");
const modelInput = document.getElementById("model-input");
const apiKeyGroup = document.getElementById("api-key-group");
const apiKeyInput = document.getElementById("api-key-input");
const btnSaveSettings = document.getElementById("btn-save-settings");
const settingsFeedback = document.getElementById("settings-feedback");

// Initialization
document.addEventListener("DOMContentLoaded", () => {
    loadSettings();
    detectConnectionAndLoad();
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    settingsTrigger.addEventListener("click", () => {
        settingsModal.classList.remove("hidden");
        settingsFeedback.style.display = "none";
    });
    modalClose.addEventListener("click", () => settingsModal.classList.add("hidden"));
    
    providerSelect.addEventListener("change", () => {
        const val = providerSelect.value;
        if (val === "ollama") {
            apiKeyGroup.classList.add("hidden");
            modelInput.value = "llama3";
        } else {
            apiKeyGroup.classList.remove("hidden");
            if (val === "openai") modelInput.value = "gpt-4o-mini";
            else if (val === "anthropic") modelInput.value = "claude-3-5-sonnet-20241022";
            else if (val === "gemini") modelInput.value = "gemini-1.5-flash";
        }
    });

    btnSaveSettings.addEventListener("click", saveSettings);
    btnAnalyzeCustom.addEventListener("click", analyzeCustomLogs);
    btnClear.addEventListener("click", () => {
        customLogsInput.value = "";
        clearAnalysis();
    });
    btnStream.addEventListener("click", toggleLiveStream);
    btnRunPlaybook.addEventListener("click", executePlaybook);
    btnChatSend.addEventListener("click", sendMessage);
    chatInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendMessage();
    });
}

// Load configurations
function loadSettings() {
    const saved = localStorage.getItem("soc_analyst_config");
    if (saved) {
        state.config = JSON.parse(saved);
        providerSelect.value = state.config.provider;
        modelInput.value = state.config.model;
        apiKeyInput.value = state.config.api_key;
        
        if (state.config.provider !== "ollama") {
            apiKeyGroup.classList.remove("hidden");
        }
    }
}

// Save Settings
async function saveSettings() {
    state.config.provider = providerSelect.value;
    state.config.model = modelInput.value;
    state.config.api_key = apiKeyInput.value;
    
    localStorage.setItem("soc_analyst_config", JSON.stringify(state.config));
    
    settingsFeedback.style.display = "block";
    settingsFeedback.className = "feedback-msg";
    settingsFeedback.textContent = "Testing connection...";
    
    if (state.isOffline) {
        settingsFeedback.classList.add("feedback-success");
        settingsFeedback.textContent = "Settings saved (Running in Offline/GitHub Pages Sandbox).";
        setTimeout(() => settingsModal.classList.add("hidden"), 1500);
        return;
    }

    try {
        const res = await fetch("/api/test-ollama", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(state.config)
        });
        const data = await res.json();
        if (data.status === "connected") {
            settingsFeedback.classList.add("feedback-success");
            settingsFeedback.textContent = data.message;
            updateStatusPill(true, "Ollama: Connected");
            setTimeout(() => settingsModal.classList.add("hidden"), 1500);
        } else {
            settingsFeedback.classList.add("feedback-error");
            settingsFeedback.textContent = data.message;
            updateStatusPill(false, "Ollama: Offline");
        }
    } catch (e) {
        settingsFeedback.classList.add("feedback-error");
        settingsFeedback.textContent = "Could not connect to API server. Sandbox active.";
    }
}

// Detect connection mode
async function detectConnectionAndLoad() {
    try {
        const res = await fetch("/api/scenarios");
        if (res.ok) {
            const data = await res.ok ? await res.json() : null;
            if (data) {
                state.scenarios = data;
                state.isOffline = false;
                updateStatusPill(true, "API Connected");
                renderScenariosList(data);
                return;
            }
        }
    } catch (e) {
        console.warn("API Server unreachable. Activating GitHub Pages sandbox.");
    }
    
    // Offline / GitHub Pages fallback
    state.isOffline = true;
    updateStatusPill(true, "Sandbox Mode (No API)");
    
    // Map static scenarios to state
    state.scenarios = Object.keys(CLIENT_SCENARIOS).map(k => ({
        id: k,
        title: CLIENT_SCENARIOS[k].title,
        description: CLIENT_SCENARIOS[k].description,
        log_count: CLIENT_SCENARIOS[k].logs.length
    }));
    renderScenariosList(state.scenarios);
}

function updateStatusPill(active, text) {
    if (state.isOffline) {
        ollamaPill.className = "status-pill status-loading";
        ollamaPill.querySelector(".status-text").textContent = "Sandbox: GitHub Pages";
    } else {
        ollamaPill.className = "status-pill " + (active ? "status-active" : "status-error");
        ollamaPill.querySelector(".status-text").textContent = text;
    }
}

function renderScenariosList(scenarios) {
    scenariosList.innerHTML = "";
    scenarios.forEach(sc => {
        const item = document.createElement("button");
        item.className = "scenario-item";
        item.innerHTML = `
            <h4>${sc.title}</h4>
            <p>${sc.description}</p>
            <div style="font-size: 0.65rem; color: var(--primary); margin-top: 0.35rem; font-family: var(--font-mono)">
                LOG COUNT: ${sc.log_count} events
            </div>
        `;
        item.addEventListener("click", () => selectScenario(sc.id, item));
        scenariosList.appendChild(item);
    });
}

// Select Scenario
async function selectScenario(id, element) {
    if (state.liveStreamInterval) toggleLiveStream();
    
    document.querySelectorAll(".scenario-item").forEach(item => item.classList.remove("active"));
    element.classList.add("active");
    
    showLoading(true);
    
    // Print logs to terminal
    logTerminal.innerHTML = "";
    const logs = state.isOffline ? CLIENT_SCENARIOS[id].logs : null;
    const title = state.isOffline ? CLIENT_SCENARIOS[id].title : "";
    
    printTerminalLine(`> Selected template: ${title || id}`, "system-msg");
    printTerminalLine(`> Injecting logs into parser...`, "system-msg");
    
    if (state.isOffline) {
        logs.forEach(log => {
            const levelClass = getLevelClass(log.rule.level);
            printTerminalLine(`[${log.timestamp}] [Rule ${log.rule.id}] [LVL ${log.rule.level}] ${log.rule.description} | Src: ${log.data.srcip || 'N/A'}`, levelClass);
        });
        
        // Offline analytical engine
        setTimeout(() => {
            const analysis = clientAnalyzeLogs(logs);
            renderAnalysis(analysis);
            showLoading(false);
        }, 1000);
    } else {
        try {
            const detailsRes = await fetch(`/api/scenarios/${id}`);
            const details = await detailsRes.json();
            details.logs.forEach(log => {
                const levelClass = getLevelClass(log.rule.level);
                printTerminalLine(`[${log.timestamp}] [Rule ${log.rule.id}] [LVL ${log.rule.level}] ${log.rule.description}`, levelClass);
            });
            
            const analysisRes = await fetch(`/api/scenarios/${id}/analyze`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(state.config)
            });
            const result = await analysisRes.json();
            renderAnalysis(result.analysis);
        } catch (e) {
            printTerminalLine(`> Analysis failed. Falling back to local rules...`, "level-high");
            const fallback = clientAnalyzeLogs(CLIENT_SCENARIOS[id].logs);
            renderAnalysis(fallback);
        } finally {
            showLoading(false);
        }
    }
}

// Client Side Rule Parser
function clientAnalyzeLogs(logs) {
    const descConcat = logs.map(l => l.rule.description + " " + JSON.stringify(l.data)).join(" ").toLowerCase();
    
    let priority = "Low";
    let threat_name = "Suspicious Host Event";
    let explanation = "System identified suspicious patterns in local agent logs.";
    let remediation = "Inspect target system processes and active shell handles.";
    let mitre_id = "T1059";
    let confidence = 80;
    
    if (descConcat.includes("ransomware") || descConcat.includes("locked") || descConcat.includes("shadow copies")) {
        priority = "Critical";
        threat_name = "Ransomware Infiltration & Encryption";
        explanation = "Multiple fast file writes renaming files to .locked extension, followed by automated volume shadow copy deletion.";
        remediation = "Isolate host system from network. Kill malicious invoice.exe process. Restore files from backup.";
        mitre_id = "T1486";
    } else if (descConcat.includes("union select") || descConcat.includes("sql")) {
        priority = "High";
        threat_name = "SQL Injection Data Leakage";
        explanation = "External client injected SQL Union payloads into parameters, exposing MySQL backend schemas and password database.";
        remediation = "Block source IP 203.0.113.15 at edge firewall. Apply parameter validation inside API routing.";
        mitre_id = "T1190";
    } else if (descConcat.includes("brute force") || descConcat.includes("authentication failed") || descConcat.includes("sshd: auth")) {
        if (descConcat.includes("success") || descConcat.includes("sshd: authentication success")) {
            priority = "High";
            threat_name = "Successful SSH Brute Force";
            explanation = "Multiple login failures on prod-web-server followed by an immediate successful authentication from the same external IP.";
            remediation = "Revoke compromise ssh user session. Disable password access and enforce strict Key-Based auth.";
            mitre_id = "T1110";
        } else {
            priority = "Medium";
            threat_name = "SSH Brute Force Attempt";
            explanation = "Automated scripting brute-forcing root/admin user accounts. Connections blocked or failed.";
            remediation = "Add ssh source IP block rules in local IPtables.";
            mitre_id = "T1110";
        }
    } else if (descConcat.includes("beacon") || descConcat.includes("repetitive connections")) {
        priority = "High";
        threat_name = "Cobalt Strike C2 Beaconing";
        explanation = "Internal workstation making regular outbound HTTP connections to unclassified external IP at strict 10s intervals.";
        remediation = "Block outbound egress port 443 connections to IP 45.33.22.11. Run malware scan on local workstation.";
        mitre_id = "T1071";
    }
    
    const mitre_info = MITRE_LOOKUP[mitre_id] || { name: "Unknown", tactic: "Execution", description: "Unknown threat pattern." };
    
    return {
        threat_name,
        priority,
        mitre_id,
        mitre_name: mitre_info.name,
        mitre_tactic: mitre_info.tactic,
        mitre_description: mitre_info.description,
        explanation,
        remediation,
        confidence,
        timeline: logs.map(l => `${l.timestamp} - ${l.agent?.name || 'host'}: ${l.rule.description}`)
    };
}

// Custom Logs
async function analyzeCustomLogs() {
    const rawVal = customLogsInput.value.trim();
    if (!rawVal) return;
    
    let parsedLogs;
    try {
        parsedLogs = JSON.parse(rawVal);
        if (!Array.isArray(parsedLogs)) parsedLogs = [parsedLogs];
    } catch (e) {
        parsedLogs = [{
            timestamp: new Date().toISOString(),
            source: "manual",
            rule: { id: "9999", level: 5, description: "Manual Log Entry" },
            data: { raw: rawVal }
        }];
    }
    
    if (state.liveStreamInterval) toggleLiveStream();
    showLoading(true);
    
    if (state.isOffline) {
        setTimeout(() => {
            const analysis = clientAnalyzeLogs(parsedLogs);
            renderAnalysis(analysis);
            showLoading(false);
        }, 1000);
    } else {
        try {
            const res = await fetch("/api/analyze-custom", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ logs: parsedLogs, config: state.config })
            });
            const result = await res.json();
            renderAnalysis(result.analysis);
        } catch (e) {
            const fallback = clientAnalyzeLogs(parsedLogs);
            renderAnalysis(fallback);
        } finally {
            showLoading(false);
        }
    }
}

// Live Stream
function toggleLiveStream() {
    if (state.liveStreamInterval) {
        clearInterval(state.liveStreamInterval);
        state.liveStreamInterval = null;
        btnStream.classList.remove("active");
        btnStream.innerHTML = `<span class="pulse-icon"></span> Stream Live`;
        printTerminalLine(`> Live stream paused.`, "system-msg");
    } else {
        document.querySelectorAll(".scenario-item").forEach(item => item.classList.remove("active"));
        logTerminal.innerHTML = "";
        state.streamLogsCache = [];
        printTerminalLine(`> Connection to local SIEM sensor established...`, "system-msg");
        printTerminalLine(`> Streaming live events in real-time...`, "system-msg");
        
        btnStream.classList.add("active");
        btnStream.innerHTML = `<span class="pulse-icon"></span> Pausing Stream`;
        
        state.liveStreamInterval = setInterval(async () => {
            let log;
            if (state.isOffline) {
                log = generateClientLiveLog();
            } else {
                try {
                    const res = await fetch("/api/live-stream");
                    log = await res.json();
                } catch (e) {
                    log = generateClientLiveLog();
                }
            }
            
            state.streamLogsCache.push(log);
            if (state.streamLogsCache.length > 20) state.streamLogsCache.shift();
            
            const levelClass = getLevelClass(log.rule.level);
            printTerminalLine(`[${log.timestamp}] [${log.source.toUpperCase()}] [LVL ${log.rule.level}] ${log.rule.description}`, levelClass);
            
            if (log.rule.level >= 6) {
                printTerminalLine(`[ALERT] High priority event! Triggering auto-analysis...`, "level-high");
                triggerOfflineStreamAnalysis(state.streamLogsCache.slice(-5));
            }
        }, 2500);
    }
}

function generateClientLiveLog() {
    const sources = ["wazuh", "syslog", "nginx-access", "sysmon"];
    const src = sources[Math.floor(Math.random() * sources.length)];
    const levels = [3, 4, 5, 8, 10];
    const lvl = levels[Math.floor(Math.random() * levels.length)];
    const now = new Date().toISOString();
    
    let desc = "Normal user system query check";
    if (lvl >= 8) {
        desc = src === "wazuh" ? "sshd: Authentication failed for root" : "Nginx: GET SQL Injection attempt";
    }
    
    return {
        timestamp: now,
        source: src,
        agent: { name: "prod-web-server" },
        rule: { id: "100" + lvl, level: lvl, description: desc },
        data: { srcip: "192.168.1.10" }
    };
}

function triggerOfflineStreamAnalysis(logs) {
    const analysis = clientAnalyzeLogs(logs);
    renderAnalysis(analysis);
    printTerminalLine(`[AI REPORT] Analysis complete: ${analysis.threat_name} (Priority: ${analysis.priority})`, "level-low");
}

// Render analysis details
function renderAnalysis(analysis) {
    state.activeContext = analysis;
    
    insightsEmpty.classList.add("hidden");
    insightsWrapper.classList.remove("hidden");
    
    threatPriority.textContent = analysis.priority.toUpperCase();
    threatPriority.className = "priority-tag " + getPriorityBadgeClass(analysis.priority);
    
    threatConfidence.textContent = `${analysis.confidence}% CONFIDENCE`;
    threatName.textContent = analysis.threat_name;
    threatHeader.className = "threat-header-card " + getPriorityBorderClass(analysis.priority);
    
    mitreTactic.textContent = analysis.mitre_tactic;
    mitreTechnique.textContent = `${analysis.mitre_id} // ${analysis.mitre_name}`;
    mitreDescription.textContent = analysis.mitre_description;
    
    threatExplanation.textContent = analysis.explanation;
    
    timelineList.innerHTML = "";
    analysis.timeline.forEach(line => {
        const item = document.createElement("li");
        item.className = "timeline-item";
        let timeStr = "";
        let descStr = line;
        const parts = line.split(" - ");
        if (parts.length > 1) {
            timeStr = parts[0];
            descStr = parts.slice(1).join(" - ");
        }
        item.innerHTML = `
            ${timeStr ? `<span class="timeline-time">${timeStr}</span>` : ""}
            <span class="timeline-desc">${descStr}</span>
        `;
        timelineList.appendChild(item);
    });
    
    remediationEmpty.classList.add("hidden");
    remediationWrapper.classList.remove("hidden");
    containmentStatus.classList.add("hidden");
    btnRunPlaybook.disabled = false;
    btnRunPlaybook.textContent = "Execute Auto-Containment";
    
    remediationText.textContent = analysis.remediation;
    
    chatMessages.innerHTML = `
        <div class="chat-msg ai-msg">
            <div class="msg-meta">AI SOC Analyst</div>
            <div class="msg-text">Analysis complete. Ask me details about processes, users, or host files, or request custom firewall scripts.</div>
        </div>
    `;
}

function clearAnalysis() {
    state.activeContext = null;
    insightsEmpty.classList.remove("hidden");
    insightsWrapper.classList.add("hidden");
    remediationEmpty.classList.remove("hidden");
    remediationWrapper.classList.add("hidden");
}

// Chat
async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text || !state.activeContext) return;
    
    appendChatBubble(text, "operator", "user-msg");
    chatInput.value = "";
    
    const typingBubble = appendChatBubble("Thinking...", "AI SOC Analyst", "ai-msg");
    
    if (state.isOffline) {
        setTimeout(() => {
            typingBubble.remove();
            const responseText = getClientChatResponse(state.activeContext, text);
            appendChatBubble(responseText, "AI SOC Analyst", "ai-msg");
        }, 1000);
        return;
    }

    try {
        const res = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ context: state.activeContext, message: text, config: state.config })
        });
        const data = await res.json();
        typingBubble.remove();
        appendChatBubble(data.response, "AI SOC Analyst", "ai-msg");
    } catch (e) {
        typingBubble.remove();
        const fallbackResponse = getClientChatResponse(state.activeContext, text);
        appendChatBubble(fallbackResponse, "AI SOC Analyst", "ai-msg");
    }
}

function getClientChatResponse(context, message) {
    const msg_lower = message.toLowerCase();
    const attacker_ip = "198.51.100.42";
    
    if (msg_lower.includes("block") || msg_lower.includes("firewall") || msg_lower.includes("iptables")) {
        return `To contain the attack on the network level, deploy these firewall rules immediately:
\`\`\`bash
# Drop all incoming packets from target IP
sudo iptables -A INPUT -s ${attacker_ip} -j DROP

# Enable logging for blocked connection drops
sudo iptables -A INPUT -s ${attacker_ip} -m limit --limit 5/min -j LOG --log-prefix "IP_BLOCK: "
\`\`\``;
    } else if (msg_lower.includes("process") || msg_lower.includes("kill") || msg_lower.includes("pid")) {
        return `To inspect running processes and terminate suspicious activities on the host:
\`\`\`bash
# List active processes sorted by CPU and grep target keywords
ps auxwf | grep -E "invoice|shadow"

# Terminate process PID (replace PID with target process id)
sudo kill -9 PID
\`\`\``;
    } else if (msg_lower.includes("mitre") || msg_lower.includes("attack")) {
        return `This event maps to MITRE ATT&CK technique **${context.mitre_id}** (${context.mitre_name}) under the Tactic **${context.mitre_tactic}**. This represents common adversary behavior for the initial compromise or execution sequence.`;
    }
    
    return `Based on current investigation context (**${context.threat_name}**), I advise locking active user sessions on the system, auditing configuration file privileges, and analyzing network connections using:
\`\`\`bash
netstat -tupa
\`\`\``;
}

function appendChatBubble(text, author, className) {
    const bubble = document.createElement("div");
    bubble.className = `chat-msg ${className}`;
    const formattedText = text.replace(/\n/g, "<br>");
    bubble.innerHTML = `
        <div class="msg-meta">${author}</div>
        <div class="msg-text">${formattedText}</div>
    `;
    chatMessages.appendChild(bubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return bubble;
}

// Containment Execution
function executePlaybook() {
    if (!state.activeContext) return;
    
    btnRunPlaybook.disabled = true;
    btnRunPlaybook.textContent = "Deploying Rules...";
    containmentStatus.classList.remove("hidden");
    containmentStatus.innerHTML = "";
    
    const steps = [
        `[STATUS] Connecting to remote endpoint agents...`,
        `[STATUS] Target Host: prod-web-server`,
        `[EXEC] Running containment scripts...`,
        `[EXEC] Block rule deployed: iptables drop rule for threat IP`,
        `[EXEC] Process termination completed.`,
        `[STATUS] Host isolated successfully.`,
        `[SUCCESS] Incident contained. core network secured.`
    ];
    
    let currentStep = 0;
    const interval = setInterval(() => {
        if (currentStep < steps.length) {
            const line = document.createElement("div");
            line.className = "terminal-line " + (steps[currentStep].startsWith("[SUCCESS]") ? "level-low" : "system-msg");
            line.textContent = steps[currentStep];
            containmentStatus.appendChild(line);
            containmentStatus.scrollTop = containmentStatus.scrollHeight;
            currentStep++;
        } else {
            clearInterval(interval);
            btnRunPlaybook.textContent = "Containment Executed";
        }
    }, 1000);
}

// Helpers
function getLevelClass(level) {
    if (level >= 10) return "level-crit";
    if (level >= 7) return "level-high";
    if (level >= 5) return "level-med";
    return "level-low";
}
function getPriorityBadgeClass(priority) {
    const p = priority.toLowerCase();
    if (p === "critical") return "text-critical";
    if (p === "high") return "text-high";
    if (p === "medium") return "text-medium";
    return "text-low";
}
function getPriorityBorderClass(priority) {
    const p = priority.toLowerCase();
    if (p === "critical") return "priority-critical";
    if (p === "high") return "priority-high";
    if (p === "medium") return "priority-medium";
    return "priority-low";
}
function printTerminalLine(text, className) {
    const line = document.createElement("div");
    line.className = `terminal-line ${className}`;
    line.textContent = text;
    logTerminal.appendChild(line);
    logTerminal.scrollTop = logTerminal.scrollHeight;
}
function showLoading(show) {
    if (show) loadingOverlay.classList.remove("hidden");
    else loadingOverlay.classList.add("hidden");
}
