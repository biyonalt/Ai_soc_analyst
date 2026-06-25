# backend/simulators.py

import time
import random
from datetime import datetime

SCENARIOS = {
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
}

def generate_live_log():
    """
    Generates a single random log to simulate a live event stream.
    """
    sources = ["wazuh", "syslog", "nginx-access", "mysql-error", "sysmon", "zeek-conn"]
    src = random.choice(sources)
    ip_last_octet = random.randint(2, 254)
    ext_ip = f"{random.randint(50, 220)}.{random.randint(10, 250)}.{random.randint(5, 250)}.{random.randint(2, 254)}"
    
    agents = [
        {"id": "001", "name": "prod-web-server", "ip": "10.0.0.5"},
        {"id": "002", "name": "nginx-ingress", "ip": "10.0.0.10"},
        {"id": "005", "name": "corp-fileserver", "ip": "10.10.1.15"},
        {"id": "008", "name": "user-workstation-8", "ip": "10.10.2.85"}
    ]
    agent = random.choice(agents)
    
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    if src == "wazuh":
        is_success = random.choice([True, False])
        if is_success:
            return {
                "timestamp": now,
                "source": src,
                "agent": agent,
                "rule": {"id": "5715", "level": 4, "description": "sshd: Successful login"},
                "data": {"srcip": ext_ip, "dstuser": "ubuntu", "port": str(random.randint(30000, 60000))}
            }
        else:
            return {
                "timestamp": now,
                "source": src,
                "agent": agent,
                "rule": {"id": "5712", "level": 6, "description": "sshd: Authentication failed"},
                "data": {"srcip": ext_ip, "dstuser": random.choice(["root", "admin", "user"]), "port": str(random.randint(30000, 60000))}
            }
            
    elif src == "syslog":
        return {
            "timestamp": now,
            "source": src,
            "agent": agent,
            "rule": {"id": "1003", "level": 3, "description": "Cron job completed successfully"},
            "data": {"job": "systemd-tmpfiles-clean.service", "status": "success"}
        }
        
    elif src == "nginx-access":
        reqs = ["GET /index.html", "POST /login", "GET /api/v1/status", "GET /wp-admin.php"]
        req = random.choice(reqs)
        status = 200
        level = 3
        desc = "Nginx: HTTP request completed"
        if "wp-admin" in req:
            status = 404
            level = 5
            desc = "Nginx: Scanning for vulnerable admin panel"
        return {
            "timestamp": now,
            "source": src,
            "agent": agent,
            "rule": {"id": "100201", "level": level, "description": desc},
            "data": {"srcip": ext_ip, "request": req, "status": status, "bytes_sent": random.randint(200, 5000)}
        }
        
    elif src == "sysmon":
        actions = ["FileCreate", "ProcessCreate", "RegistrySet"]
        act = random.choice(actions)
        return {
            "timestamp": now,
            "source": src,
            "agent": agent,
            "rule": {"id": "92000", "level": 4, "description": f"Sysmon: Registry or Process activity"},
            "data": {"process": "C:\\Windows\\System32\\svchost.exe", "action": act, "detail": "standard svchost.exe behavior"}
        }
        
    else: # zeek-conn
        return {
            "timestamp": now,
            "source": src,
            "agent": agent,
            "rule": {"id": "80200", "level": 3, "description": "Zeek: Normal TCP connection establish"},
            "data": {"srcip": agent["ip"], "dstip": ext_ip, "dstport": random.choice([80, 443]), "bytes_sent": random.randint(100, 2000)}
        }
