# backend/analyst.py

import json
import requests
from backend.mitre import map_alert_to_mitre

OLLAMA_URL = "http://localhost:11434/api/generate"

def analyze_logs_locally(logs: list) -> dict:
    """
    Fallback deterministic analysis when LLM is unavailable or for initial parsing.
    """
    # Simple rule-based logic to extract basic insights
    desc_concat = " ".join([l.get("rule", {}).get("description", "") + " " + str(l.get("data", {})) for l in logs]).lower()
    
    # Run MITRE mapping on concat description
    tech_id, tech_info = map_alert_to_mitre(desc_concat)
    
    # Base heuristic logic
    priority = "Low"
    threat_name = "Suspicious Event"
    explanation = "Logs indicate potential suspicious activity on the network or host."
    mitigation = tech_info.get("mitigation", "Monitor host activity and check network firewall logs.")
    
    # Elevate priority and detail based on keyword presence
    if "ransomware" in desc_concat or "locked" in desc_concat or "shadow copies" in desc_concat:
        priority = "Critical"
        threat_name = "Ransomware Activity Detected"
        explanation = "File modification rates and backup deletion commands point to ransomware execution."
        mitigation = "Isolate host from network immediately. Stop affected processes. Restore from offsite backup."
    elif "union select" in desc_concat or "sql injection" in desc_concat or "load_file" in desc_concat:
        priority = "High"
        threat_name = "SQL Injection Data Leak"
        explanation = "Attacker targeted API endpoints with SQL union payloads, causing data exposure."
        mitigation = "Block attacker IP at WAF. Validate inputs in web app query parameters. Rotate DB credentials."
    elif "brute force" in desc_concat or "authentication failed" in desc_concat or "sshd: authentication failed" in desc_concat:
        # Check if login success also present
        if "authentication success" in desc_concat or "successful login" in desc_concat:
            priority = "High"
            threat_name = "Successful Brute Force Attack"
            explanation = "Multiple authentication failures followed by a successful login from the same external IP."
            mitigation = "Revoke compromise user session. Enable MFA. Lock ssh access from external IP."
        else:
            priority = "Medium"
            threat_name = "SSH Brute Force Attempt"
            explanation = "Multiple failed SSH login attempts detected from a single external host."
            mitigation = "Temporarily block source IP using fail2ban or firewall rules. Enforce key-based auth."
    elif "beacon" in desc_concat or "c2" in desc_concat or "repetitive connections" in desc_concat:
        priority = "High"
        threat_name = "C2 Beaconing Identified"
        explanation = "Internal client exhibits automated, periodic connections to an external unclassified IP address."
        mitigation = "Block destination IP on egress firewall. Scan internal workstation for remote access trojans."
        
    return {
        "threat_name": threat_name,
        "priority": priority,
        "mitre_id": tech_id,
        "mitre_name": tech_info["name"],
        "mitre_tactic": tech_info["tactic"],
        "mitre_description": tech_info["description"],
        "explanation": explanation,
        "remediation": mitigation,
        "confidence": 85,
        "timeline": [f"{l['timestamp']} - {l.get('agent', {}).get('name', 'host')}: {l['rule']['description']}" for l in logs]
    }

def build_prompt(logs: list) -> str:
    logs_str = json.dumps(logs, indent=2)
    prompt = f"""
You are a highly skilled Senior Tier 3 SOC Analyst.
Analyze the following SIEM logs and output a detailed threat analysis in JSON format.

Logs:
{logs_str}

Your JSON output must follow this schema exactly:
{{
  "threat_name": "Name of the attack / threat pattern",
  "priority": "Low | Medium | High | Critical",
  "mitre_id": "MITRE ATT&CK Technique ID (e.g. T1110)",
  "mitre_name": "MITRE ATT&CK Technique Name",
  "mitre_tactic": "MITRE ATT&CK Tactic Category (e.g. Credential Access)",
  "explanation": "Simple, no-jargon explanation of what the attacker did and how they succeeded or failed.",
  "remediation": "Concrete, step-by-step remediation commands/actions for responders.",
  "confidence": integer between 0 and 100,
  "timeline": ["Chronological list of log events summarized as key moments"]
}}

Only output the raw JSON. Do not include markdown code block syntax (like ```json). Just start with {{ and end with }}.
"""
    return prompt

def query_llm(prompt: str, api_config: dict = None) -> str:
    """
    Sends prompt to selected LLM provider (Ollama, OpenAI, Anthropic, Gemini).
    """
    provider = api_config.get("provider", "ollama") if api_config else "ollama"
    
    if provider == "ollama":
        try:
            model = api_config.get("model", "llama3") if api_config else "llama3"
            response = requests.post(
                OLLAMA_URL,
                json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.1}},
                timeout=30
            )
            if response.status_code == 200:
                return response.json().get("response", "")
        except Exception as e:
            print(f"Ollama connection failed: {e}")
            
    elif provider == "openai":
        api_key = api_config.get("api_key")
        model = api_config.get("model", "gpt-4o-mini")
        if api_key:
            try:
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a cyber security analyst. Output JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1
                }
                res = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    return res.json()["choices"][0]["message"]["content"]
            except Exception as e:
                print(f"OpenAI API failed: {e}")
                
    elif provider == "anthropic":
        api_key = api_config.get("api_key")
        model = api_config.get("model", "claude-3-5-sonnet-20241022")
        if api_key:
            try:
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
                payload = {
                    "model": model,
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                }
                res = requests.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    content_list = res.json().get("content", [])
                    if content_list:
                        return content_list[0].get("text", "")
            except Exception as e:
                print(f"Anthropic API failed: {e}")
                
    elif provider == "gemini":
        api_key = api_config.get("api_key")
        if api_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1}
                }
                res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=20)
                if res.status_code == 200:
                    return res.json()["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                print(f"Gemini API failed: {e}")
                
    return ""

def analyze_logs(logs: list, api_config: dict = None) -> dict:
    """
    Main entry point for analyzing log arrays. Falls back to rule-base if LLM fails.
    """
    # Build prompt
    prompt = build_prompt(logs)
    llm_resp = query_llm(prompt, api_config)
    
    if llm_resp:
        try:
            # Clean possible markdown wrapping
            cleaned = llm_resp.strip()
            if cleaned.startswith("```"):
                # strip out markdown blocks
                lines = cleaned.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned = "\n".join(lines).strip()
            
            parsed = json.loads(cleaned)
            # Make sure MITRE details are populated properly
            if parsed.get("mitre_id"):
                tech_id = parsed["mitre_id"]
                from backend.mitre import MITRE_DATABASE
                if tech_id in MITRE_DATABASE:
                    parsed["mitre_name"] = MITRE_DATABASE[tech_id]["name"]
                    parsed["mitre_tactic"] = MITRE_DATABASE[tech_id]["tactic"]
                    parsed["mitre_description"] = MITRE_DATABASE[tech_id]["description"]
                    if not parsed.get("remediation"):
                        parsed["remediation"] = MITRE_DATABASE[tech_id]["mitigation"]
            return parsed
        except Exception as e:
            print(f"Failed to parse LLM JSON: {e}. Output was: {llm_resp}")
            
    # Fallback to local expert rules
    return analyze_logs_locally(logs)

def chat_with_analyst(context: dict, message: str, api_config: dict = None) -> str:
    """
    Allow the security operator to chat with the AI Analyst about the selected alert.
    """
    prompt = f"""
You are a Senior Tier 3 SOC Analyst assistant.
The operator is asking a question about a detected security incident.

Incident context:
{json.dumps(context, indent=2)}

Operator's Question:
"{message}"

Provide a professional, direct, and actionable response. Keep the tone focused on security investigation, containment, and forensics. If they ask for commands, provide specific Linux/Windows command examples. Do not use markdown blocks other than code blocks if showing commands.
"""
    provider = api_config.get("provider", "ollama") if api_config else "ollama"
    response_text = ""
    
    if provider == "ollama":
        try:
            model = api_config.get("model", "llama3") if api_config else "llama3"
            response = requests.post(
                OLLAMA_URL,
                json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.3}},
                timeout=30
            )
            if response.status_code == 200:
                response_text = response.json().get("response", "")
        except Exception as e:
            print(f"Ollama chat failed: {e}")
            
    elif provider == "openai":
        api_key = api_config.get("api_key")
        model = api_config.get("model", "gpt-4o-mini")
        if api_key:
            try:
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a cyber security analyst assisting a junior operator."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3
                }
                res = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    response_text = res.json()["choices"][0]["message"]["content"]
            except Exception as e:
                print(f"OpenAI chat failed: {e}")

    elif provider == "anthropic":
        api_key = api_config.get("api_key")
        model = api_config.get("model", "claude-3-5-sonnet-20241022")
        if api_key:
            try:
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
                payload = {
                    "model": model,
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3
                }
                res = requests.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    content_list = res.json().get("content", [])
                    if content_list:
                        response_text = content_list[0].get("text", "")
            except Exception as e:
                print(f"Anthropic chat failed: {e}")
                
    elif provider == "gemini":
        api_key = api_config.get("api_key")
        if api_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.3}
                }
                res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=20)
                if res.status_code == 200:
                    response_text = res.json()["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                print(f"Gemini chat failed: {e}")

    if not response_text:
        # Fallback security rules response
        msg_lower = message.lower()
        if "block" in msg_lower or "firewall" in msg_lower or "iptables" in msg_lower:
            response_text = "To contain the attack, execute these commands:\n```bash\n# Block malicious IP using iptables\nsudo iptables -A INPUT -s " + (context.get("data", {}).get("srcip", "ATTACKER_IP") if isinstance(context.get("data"), dict) else "ATTACKER_IP") + " -j DROP\n\n# Or block with UFW\nsudo ufw deny from " + (context.get("data", {}).get("srcip", "ATTACKER_IP") if isinstance(context.get("data"), dict) else "ATTACKER_IP") + "\n```"
        elif "process" in msg_lower or "kill" in msg_lower:
            response_text = "To identify and kill malicious processes:\n```bash\n# Find processes by CPU usage or executable path\nps aux | grep -i \"invoice\"\n\n# Terminate process\nsudo kill -9 <PID>\n```"
        else:
            response_text = "Based on the threat of **" + context.get("threat_name", "Security Alert") + "**, I recommend immediately checking active network connections using `netstat -tupa` or running an endpoint security scan on the affected host (" + context.get("timeline", ["Affected Host"])[0].split(" - ")[1].split(":")[0] + "). Let me know if you need specific commands for blocking IPs, checking processes, or cleaning host systems."
            
    return response_text

