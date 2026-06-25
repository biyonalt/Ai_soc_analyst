// State Management
let state = {
    scenarios: [],
    selectedScenario: null,
    activeContext: null,
    liveStreamInterval: null,
    streamLogsCache: [],
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
    checkOllamaStatus();
    loadScenarios();
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    // Settings Modal
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

    // Custom Logs
    btnAnalyzeCustom.addEventListener("click", analyzeCustomLogs);
    btnClear.addEventListener("click", () => {
        customLogsInput.value = "";
        clearAnalysis();
    });

    // Live Stream
    btnStream.addEventListener("click", toggleLiveStream);

    // Playbook Execution
    btnRunPlaybook.addEventListener("click", executePlaybook);

    // Chat
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

// Save & test configuration
async function saveSettings() {
    state.config.provider = providerSelect.value;
    state.config.model = modelInput.value;
    state.config.api_key = apiKeyInput.value;
    
    localStorage.setItem("soc_analyst_config", JSON.stringify(state.config));
    
    settingsFeedback.style.display = "block";
    settingsFeedback.className = "feedback-msg";
    settingsFeedback.textContent = "Testing connection...";
    
    if (state.config.provider === "ollama") {
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
                updateOllamaPill(true, "Ollama: Connected");
                setTimeout(() => settingsModal.classList.add("hidden"), 1500);
            } else {
                settingsFeedback.classList.add("feedback-error");
                settingsFeedback.textContent = data.message;
                updateOllamaPill(false, "Ollama: Offline");
            }
        } catch (e) {
            settingsFeedback.classList.add("feedback-error");
            settingsFeedback.textContent = "Cannot connect to local backend service.";
            updateOllamaPill(false, "Ollama: Service Error");
        }
    } else {
        // Cloud providers - assume OK once key provided
        settingsFeedback.classList.add("feedback-success");
        settingsFeedback.textContent = `Provider updated to ${state.config.provider.toUpperCase()}. Key saved.`;
        updateOllamaPill(true, `${state.config.provider.toUpperCase()} Mode`);
        setTimeout(() => settingsModal.classList.add("hidden"), 1500);
    }
}

// Check local Ollama status
async function checkOllamaStatus() {
    try {
        const res = await fetch("/api/test-ollama", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(state.config)
        });
        const data = await res.json();
        if (data.status === "connected") {
            updateOllamaPill(true, `Ollama: Ready (${state.config.model})`);
        } else {
            updateOllamaPill(false, "Ollama: Offline");
        }
    } catch (e) {
        updateOllamaPill(false, "Backend connection error");
    }
}

function updateOllamaPill(active, text) {
    ollamaPill.className = "status-pill " + (active ? "status-active" : "status-error");
    ollamaPill.querySelector(".status-text").textContent = text;
}

// Fetch Predefined Scenarios
async function loadScenarios() {
    try {
        const res = await fetch("/api/scenarios");
        const data = await res.json();
        state.scenarios = data;
        
        scenariosList.innerHTML = "";
        data.forEach(sc => {
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
    } catch (e) {
        console.error("Failed to load scenarios", e);
    }
}

// Select & Execute Scenario Analysis
async function selectScenario(id, element) {
    if (state.liveStreamInterval) {
        toggleLiveStream(); // stop streaming
    }
    
    // UI active classes
    document.querySelectorAll(".scenario-item").forEach(item => item.classList.remove("active"));
    element.classList.add("active");
    
    showLoading(true);
    
    try {
        // Fetch full logs to print to terminal
        const detailsRes = await fetch(`/api/scenarios/${id}`);
        const details = await detailsRes.json();
        
        // Print to log terminal
        logTerminal.innerHTML = "";
        printTerminalLine(`> Selected template: ${details.title}`, "system-msg");
        printTerminalLine(`> Injecting logs into parser...`, "system-msg");
        
        details.logs.forEach(log => {
            const levelClass = getLevelClass(log.rule.level);
            printTerminalLine(`[${log.timestamp}] [Rule ${log.rule.id}] [LVL ${log.rule.level}] ${log.rule.description} | Src: ${log.data.srcip || 'N/A'}`, levelClass);
        });
        
        // Trigger AI Analysis
        const analysisRes = await fetch(`/api/scenarios/${id}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(state.config)
        });
        const result = await analysisRes.json();
        
        renderAnalysis(result.analysis);
        
    } catch (e) {
        console.error(e);
        printTerminalLine(`> Analysis failed: ${e.message}`, "level-crit");
    } finally {
        showLoading(false);
    }
}

// Custom Logs Analysis
async function analyzeCustomLogs() {
    const rawVal = customLogsInput.value.trim();
    if (!rawVal) return;
    
    let parsedLogs;
    try {
        parsedLogs = JSON.parse(rawVal);
        if (!Array.isArray(parsedLogs)) {
            parsedLogs = [parsedLogs];
        }
    } catch (e) {
        // Wrap plain text in a fake log format
        parsedLogs = [{
            timestamp: new Date().toISOString(),
            source: "manual-entry",
            rule: { id: "9999", level: 5, description: "Operator manually entered raw logs" },
            data: { raw_text: rawVal }
        }];
    }
    
    if (state.liveStreamInterval) toggleLiveStream();
    
    showLoading(true);
    
    try {
        logTerminal.innerHTML = "";
        printTerminalLine(`> Parsing manual log entry...`, "system-msg");
        parsedLogs.forEach(l => {
            printTerminalLine(`[${l.timestamp || 'N/A'}] ${l.rule?.description || 'Log'}: ${JSON.stringify(l.data || l)}`, "level-med");
        });
        
        const res = await fetch("/api/analyze-custom", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                logs: parsedLogs,
                config: state.config
            })
        });
        const result = await res.json();
        renderAnalysis(result.analysis);
        
    } catch (e) {
        console.error(e);
        printTerminalLine(`> Custom analysis failed: ${e.message}`, "level-crit");
    } finally {
        showLoading(false);
    }
}

// Live Stream Simulations
function toggleLiveStream() {
    if (state.liveStreamInterval) {
        // Stop stream
        clearInterval(state.liveStreamInterval);
        state.liveStreamInterval = null;
        btnStream.classList.remove("active");
        btnStream.innerHTML = `<span class="pulse-icon"></span> Stream Live`;
        printTerminalLine(`> Live stream paused.`, "system-msg");
    } else {
        // Start stream
        document.querySelectorAll(".scenario-item").forEach(item => item.classList.remove("active"));
        logTerminal.innerHTML = "";
        state.streamLogsCache = [];
        printTerminalLine(`> Connection to local SIEM sensor established...`, "system-msg");
        printTerminalLine(`> Streaming live events in real-time...`, "system-msg");
        
        btnStream.classList.add("active");
        btnStream.innerHTML = `<span class="pulse-icon"></span> Pausing Stream`;
        
        state.liveStreamInterval = setInterval(async () => {
            try {
                const res = await fetch("/api/live-stream");
                const log = await res.json();
                
                // Add to stream log cache
                state.streamLogsCache.push(log);
                if (state.streamLogsCache.length > 20) state.streamLogsCache.shift();
                
                const levelClass = getLevelClass(log.rule.level);
                printTerminalLine(`[${log.timestamp}] [${log.source.toUpperCase()}] [LVL ${log.rule.level}] ${log.rule.description}`, levelClass);
                
                // Auto-trigger analysis if high-priority rules found in real time
                if (log.rule.level >= 6) {
                    printTerminalLine(`[ALERT] High level event detected! Requesting auto investigation...`, "level-high");
                    analyzeActiveLogs(state.streamLogsCache.slice(-5));
                }
            } catch (e) {
                console.error("Live stream connection lost", e);
            }
        }, 2500);
    }
}

async function analyzeActiveLogs(logs) {
    // Show sub-spinner to show real-time analysis
    printTerminalLine(`> Sending recent logs for AI analysis...`, "system-msg");
    try {
        const res = await fetch("/api/analyze-custom", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                logs: logs,
                config: state.config
            })
        });
        const result = await res.json();
        renderAnalysis(result.analysis);
        printTerminalLine(`[AI REPORT] Analysis complete: ${result.analysis.threat_name} (Priority: ${result.analysis.priority})`, "level-low");
    } catch (e) {
        console.error("Auto analysis failed", e);
    }
}

// Render Results on UI
function renderAnalysis(analysis) {
    state.activeContext = analysis;
    
    // Reveal middle insights panel
    insightsEmpty.classList.add("hidden");
    insightsWrapper.classList.remove("hidden");
    
    // Set Header priority
    threatPriority.textContent = analysis.priority.toUpperCase();
    threatPriority.className = "priority-tag " + getPriorityBadgeClass(analysis.priority);
    
    threatConfidence.textContent = `${analysis.confidence || 85}% CONFIDENCE`;
    threatName.textContent = analysis.threat_name;
    
    // Header Border Color based on priority
    threatHeader.className = "threat-header-card " + getPriorityBorderClass(analysis.priority);
    
    // MITRE Mapping
    mitreTactic.textContent = analysis.mitre_tactic || "Unknown";
    mitreTechnique.textContent = `${analysis.mitre_id || 'TXXXX'} // ${analysis.mitre_name || 'N/A'}`;
    mitreDescription.textContent = analysis.mitre_description || "No technique details available.";
    
    // Explanation
    threatExplanation.textContent = analysis.explanation;
    
    // Timeline
    timelineList.innerHTML = "";
    if (analysis.timeline && analysis.timeline.length > 0) {
        analysis.timeline.forEach(line => {
            const item = document.createElement("li");
            item.className = "timeline-item";
            
            // Extract timestamp if formatted as 'timestamp - event'
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
    } else {
        timelineList.innerHTML = `<li class="timeline-item"><span class="timeline-desc">No events parsed in timeline.</span></li>`;
    }
    
    // Reveal right panel mitigation
    remediationEmpty.classList.add("hidden");
    remediationWrapper.classList.remove("hidden");
    containmentStatus.classList.add("hidden");
    btnRunPlaybook.disabled = false;
    btnRunPlaybook.textContent = "Execute Auto-Containment";
    
    remediationText.textContent = analysis.remediation || "Check host status and isolate.";
    
    // Reset Chat panel to welcome msg
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

// Interactive chat
async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text || !state.activeContext) return;
    
    // Append User message
    appendChatBubble(text, "operator", "user-msg");
    chatInput.value = "";
    
    // Append typing message
    const typingBubble = appendChatBubble("Thinking...", "AI SOC Analyst", "ai-msg");
    
    try {
        const res = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                context: state.activeContext,
                message: text,
                config: state.config
            })
        });
        const data = await res.json();
        
        // Remove typing bubble and add final response
        typingBubble.remove();
        appendChatBubble(data.response, "AI SOC Analyst", "ai-msg");
        
    } catch (e) {
        typingBubble.remove();
        appendChatBubble(`Error reaching AI backend: ${e.message}`, "System", "ai-msg");
    }
}

function appendChatBubble(text, author, className) {
    const bubble = document.createElement("div");
    bubble.className = `chat-msg ${className}`;
    
    // Keep raw line breaks formatting
    const formattedText = text.replace(/\n/g, "<br>");
    
    bubble.innerHTML = `
        <div class="msg-meta">${author}</div>
        <div class="msg-text">${formattedText}</div>
    `;
    chatMessages.appendChild(bubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return bubble;
}

// Execute Mitigation Playbook Simulation
function executePlaybook() {
    if (!state.activeContext) return;
    
    btnRunPlaybook.disabled = true;
    btnRunPlaybook.textContent = "Deploying Rules...";
    
    containmentStatus.classList.remove("hidden");
    containmentStatus.innerHTML = "";
    
    const steps = [
        `[STATUS] Connecting to remote endpoint agents...`,
        `[STATUS] Target: ${state.activeContext.timeline[0]?.split(" - ")[1]?.split(":")[0] || 'host'}`,
        `[EXEC] Initiating containment sequence...`,
        `[EXEC] Running: sudo iptables -A INPUT -p tcp -j DROP`,
        `[EXEC] Running: kill -9 $(pgrep -i malicious)`,
        `[STATUS] Host isolated successfully.`,
        `[SUCCESS] Incident contained. Core network secured.`
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

// Helper Utilities
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
    if (show) {
        loadingOverlay.classList.remove("hidden");
    } else {
        loadingOverlay.classList.add("hidden");
    }
}
