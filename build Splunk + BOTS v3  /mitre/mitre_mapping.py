MITRE_MAPPING = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "subtechnique": False
    },
    "password_spray": {
        "tactic": "Credential Access",
        "technique_id": "T1110.003",
        "technique": "Password Spraying",
        "subtechnique": True
    },
    "recon": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "subtechnique": False
    },
    "c2": {
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "subtechnique": False
    },
    "http_c2": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Web Protocols",
        "subtechnique": True
    },
    "http_detection": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Web Protocols",
        "subtechnique": True
    },
    "dns_c2": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique": "DNS",
        "subtechnique": True
    },
    "dns_detection": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique": "DNS",
        "subtechnique": True
    },
    "powershell": {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "subtechnique": True
    },
    "process_creation": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "subtechnique": False
    },
    "windows_service": {
        "tactic": "Persistence",
        "technique_id": "T1543.003",
        "technique": "Windows Service",
        "subtechnique": True
    },
    "account_manipulation": {
        "tactic": "Persistence",
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "subtechnique": False
    },
    "suricata": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "subtechnique": False
    }
}

def get_mapping(usecase):
    return MITRE_MAPPING.get(usecase)
