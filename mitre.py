# backend/mitre.py

MITRE_DATABASE = {
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
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Remote Services to slide through the network from system to system.",
        "mitigation": "Network segmentation, disable unused protocols, monitor remote authentication logs."
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data using the same protocol as the command and control channel.",
        "mitigation": "Data Loss Prevention (DLP) agents, network traffic analysis, size limits on egress traffic."
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts to bypass security measures.",
        "mitigation": "Least privilege access control, regular credential rotation, behavior monitoring."
    }
}

def map_alert_to_mitre(alert_description: str):
    """
    Scans alert content for keywords and maps it to a MITRE technique.
    """
    desc_lower = alert_description.lower()
    if "brute" in desc_lower or "failed login" in desc_lower or "authentication failure" in desc_lower:
        return "T1110", MITRE_DATABASE["T1110"]
    elif "sql" in desc_lower or "exploit" in desc_lower or "injection" in desc_lower or "cve" in desc_lower:
        return "T1190", MITRE_DATABASE["T1190"]
    elif "shell" in desc_lower or "bash" in desc_lower or "powershell" in desc_lower or "cmd" in desc_lower:
        return "T1059", MITRE_DATABASE["T1059"]
    elif "encrypt" in desc_lower or "ransomware" in desc_lower or "locked" in desc_lower or "extension changed" in desc_lower:
        return "T1486", MITRE_DATABASE["T1486"]
    elif "beacon" in desc_lower or "c2" in desc_lower or "reverse shell" in desc_lower or "http outbound" in desc_lower:
        return "T1071", MITRE_DATABASE["T1071"]
    elif "ssh login" in desc_lower or "rdp connection" in desc_lower or "lateral" in desc_lower:
        return "T1021", MITRE_DATABASE["T1021"]
    elif "exfiltrate" in desc_lower or "upload to cloud" in desc_lower or "data transfer" in desc_lower:
        return "T1041", MITRE_DATABASE["T1041"]
    elif "admin login" in desc_lower or "privilege escalation" in desc_lower:
        return "T1078", MITRE_DATABASE["T1078"]
    
    return "Unknown", {
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": "No direct matching technique found. Requires deep inspection.",
        "mitigation": "Perform standard threat hunting and incident response triage."
    }
