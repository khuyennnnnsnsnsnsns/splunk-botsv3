# SOC Automation with Splunk, Python and MITRE ATT&CK

A Security Operations Center (SOC) automation project that integrates **Splunk Enterprise**, **Python**, **MITRE ATT&CK**, and the **Boss of the SOC v3 (BOTSv3)** dataset to automate security event analysis, detection, alert normalization, and ATT&CK coverage evaluation.

The project was developed as part of a graduation thesis focusing on building an automated workflow for detecting and analyzing cybersecurity events using SIEM data.

---

## Overview

Traditional SOC workflows often require analysts to manually execute searches, review security events, classify alerts, and map detected activities to security frameworks.

This project automates part of that process by using Python to communicate with Splunk through the REST API, execute multiple detection use cases, normalize detection results, and map them to the MITRE ATT&CK framework.

The overall workflow is:

```text
BOTSv3 Dataset
      |
      v
Splunk Enterprise
(index=botsv3)
      |
      | Splunk REST API
      v
Python Orchestrator
      |
      v
Detection Engine
      |
      v
Alert Manager
      |
      v
MITRE ATT&CK Mapping
      |
      v
Normalized Alerts / Coverage Reports
      |
      v
Splunk Visualization
```

---

## Objectives

The main objectives of this project are:

- Centralize BOTSv3 security telemetry in Splunk Enterprise.
- Automate detection queries using Python.
- Implement multiple SOC detection use cases.
- Normalize detection results into a consistent alert format.
- Map detection capabilities to MITRE ATT&CK techniques.
- Evaluate ATT&CK coverage within the selected detection scope.
- Export detection and ATT&CK coverage results for further analysis.
- Support visualization and investigation in Splunk.

---

## Technologies

The project uses:

- **Splunk Enterprise**
- **Python**
- **Splunk REST API**
- **MITRE ATT&CK**
- **Boss of the SOC v3 (BOTSv3)**
- **SPL – Search Processing Language**
- **JSON / JSONL**
- Windows Event Logs
- Sysmon
- Network telemetry
- Suricata

---

## Project Architecture

The system consists of several main components.

### Splunk Enterprise

Splunk stores and processes telemetry from the BOTSv3 dataset.

The primary dataset is queried from:

```text
index=botsv3
```

Splunk is responsible for:

- Event storage
- SPL execution
- Security telemetry analysis
- Detection data retrieval
- Dashboard visualization

---

### Python Orchestrator

`main.py` acts as the main orchestrator of the project.

It coordinates the execution of detection modules and manages the overall detection workflow.

```text
main.py
   |
   +-- Brute Force Detection
   +-- Reconnaissance Detection
   +-- C2 Detection
   +-- PowerShell Detection
   +-- Process Creation Detection
   +-- DNS Detection
   +-- HTTP Detection
   +-- Suricata Detection
   +-- Windows Service Detection
   +-- Account Manipulation Detection
```

---

### Splunk Client

`splunk_client.py` handles communication between Python and Splunk Enterprise through the Splunk REST API.

The final implementation uses Splunk search jobs with blocking execution and retrieves the complete search results using the generated Search ID (`SID`).

Conceptually:

```text
Python
   |
   | POST /services/search/jobs
   | exec_mode=blocking
   v
Splunk Search Job
   |
   | SID
   v
GET /services/search/jobs/{sid}/results
   |
   | output_mode=json
   | count=0
   v
Complete Search Results
```

This approach ensures that the detection modules process finalized Splunk search results rather than intermediate streaming results.

---

## Detection Use Cases

The current version implements **10 detection use cases**.

| # | Detection Module | Security Activity | MITRE ATT&CK |
|---|---|---|---|
| 1 | `brute_force.py` | Brute Force | T1110 |
| 2 | `recon.py` | Network Service Scanning | T1046 |
| 3 | `c2.py` | Command and Control | T1071.001 |
| 4 | `powershell.py` | PowerShell Execution | T1059.001 |
| 5 | `process_creation.py` | Command / Process Execution | T1059 |
| 6 | `dns_detection.py` | DNS-based C2 Activity | T1071.004 |
| 7 | `http_detection.py` | HTTP-based C2 Activity | T1071.001 |
| 8 | `suricata.py` | Exploit / Network Detection | T1190 |
| 9 | `windows_service.py` | Windows Service Persistence | T1543.003 |
| 10 | `account_manipulation.py` | Account Manipulation | T1098 |

---

## MITRE ATT&CK Coverage

The project defines a selected ATT&CK target set consisting of **11 techniques/sub-techniques**:

```text
T1190       Exploit Public-Facing Application

T1059       Command and Scripting Interpreter
T1059.001   PowerShell

T1110       Brute Force
T1110.003   Password Spraying

T1046       Network Service Scanning

T1071       Application Layer Protocol
T1071.001   Web Protocols
T1071.004   DNS

T1543.003   Windows Service

T1098       Account Manipulation
```

The implemented detection modules currently cover:

```text
10 / 11 selected techniques
```

Resulting in:

```text
MITRE ATT&CK target-set coverage: 90.91%
```

The uncovered technique in the current version is:

```text
T1110.003 – Password Spraying
```

> **Note:** The 90.91% value represents coverage of the project's selected 11-technique target set. It does not represent coverage of the entire MITRE ATT&CK framework.

---

## Experimental Results

During the final experiment, the system produced **683 normalized detection records**.

| Detection | Severity | Records |
|---|---:|---:|
| Command and Control | HIGH | 664 |
| Reconnaissance | MEDIUM | 10 |
| HTTP Detection | MEDIUM | 5 |
| Windows Service | MEDIUM | 2 |
| Account Manipulation | MEDIUM | 2 |
| Brute Force | - | 0 |
| PowerShell | - | 0 |
| Process Creation | - | 0 |
| DNS Detection | - | 0 |
| Suricata | - | 0 |

### Severity Distribution

```text
HIGH    : 664
MEDIUM  : 19
LOW     : 0
TOTAL   : 683
```

Command-and-Control candidates accounted for approximately:

```text
97.22%
```

of the generated normalized detection records.

> These records should be interpreted as **detection candidates / normalized alert records**, not as 683 confirmed cyberattacks. Detection results still require analyst validation and contextual investigation.

---

## Project Structure

```text
soc_automation/
│
├── alerts/
│   ├── __init__.py
│   └── alert_manager.py
│
├── mitre/
│   ├── __init__.py
│   ├── attack_matrix.py
│   ├── mitre_exporter.py
│   └── mitre_mapping.py
│
├── usecases/
│   ├── __init__.py
│   ├── account_manipulation.py
│   ├── brute_force.py
│   ├── c2.py
│   ├── dns_detection.py
│   ├── http_detection.py
│   ├── powershell.py
│   ├── process_creation.py
│   ├── recon.py
│   ├── suricata.py
│   └── windows_service.py
│
├── logs/
│   └── .gitkeep
│
├── config.py
├── main.py
├── splunk_client.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Component Description

### `main.py`

Main program responsible for coordinating all detection modules.

### `splunk_client.py`

Provides the communication layer between Python and the Splunk REST API.

### `config.py`

Contains the project configuration such as:

- Splunk host
- Management port
- Connection scheme
- Splunk index
- Search time range
- Output paths

Sensitive credentials should not be committed to a public repository.

### `usecases/`

Contains the individual SOC detection modules.

Each module performs a specific security detection function using Splunk search results.

### `alerts/alert_manager.py`

Normalizes results generated by different detection modules into a common alert structure.

### `mitre/mitre_mapping.py`

Maps detection use cases to MITRE ATT&CK techniques and tactics.

### `mitre/attack_matrix.py`

Defines the ATT&CK techniques included in the project's selected detection coverage scope.

### `mitre/mitre_exporter.py`

Generates MITRE ATT&CK coverage reports and exports the results for further processing and visualization.

---

## Output Files

During execution, the project can generate files such as:

```text
logs/detection.log
logs/normalized_alerts.jsonl
logs/mitre_coverage.json
logs/mitre_coverage.jsonl
```

These runtime-generated files are excluded from Git tracking through `.gitignore`.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/khuyennnnnsnsnsnsns/SOC-Automation-Splunk-BOTSv3.git
```

Move into the project directory:

```bash
cd SOC-Automation-Splunk-BOTSv3
```

Create a Python virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Splunk Configuration

The project requires a running Splunk Enterprise instance.

Example configuration:

```text
Splunk Management API:
https://127.0.0.1:8089

Dataset index:
botsv3
```

Configure the appropriate Splunk connection settings in the project before execution.

For security reasons:

- Do not commit real passwords.
- Do not commit API tokens.
- Do not store production credentials directly in a public repository.
- Environment variables or another secure secret-management method should be used for sensitive information.

---

## Running the Project

After Splunk is running and the BOTSv3 dataset has been indexed, execute:

```bash
python3 main.py
```

The orchestrator will execute the configured detection use cases and generate normalized detection results.

---

## Detection Workflow

A simplified detection workflow is:

```text
1. BOTSv3 telemetry is stored in Splunk
              |
              v
2. Python sends SPL searches through the Splunk REST API
              |
              v
3. Splunk executes the search
              |
              v
4. Python retrieves finalized results
              |
              v
5. Detection modules analyze the results
              |
              v
6. Alert Manager normalizes detection records
              |
              v
7. MITRE ATT&CK techniques are assigned
              |
              v
8. ATT&CK coverage is calculated
              |
              v
9. JSON / JSONL reports are generated
              |
              v
10. Results can be re-ingested into Splunk for visualization
```

---

## Key Features

- Automated Splunk detection execution
- Modular detection architecture
- Centralized alert normalization
- MITRE ATT&CK technique mapping
- ATT&CK target-set coverage calculation
- JSON and JSONL reporting
- SOC-oriented security analytics
- BOTSv3-based experimental environment
- Extensible Python detection modules

---

## Limitations

The current implementation has several limitations.

First, the detection rules are evaluated using the BOTSv3 dataset and therefore do not represent all possible behaviors that may occur in a production environment.

Second, some detection rules rely on heuristic conditions. A generated alert should therefore be treated as a candidate for investigation rather than definitive proof of malicious activity.

Third, MITRE ATT&CK coverage is calculated only against the project's selected set of 11 techniques and should not be interpreted as coverage of the complete ATT&CK Enterprise matrix.

Finally, the current project focuses primarily on detection and analysis rather than full incident response orchestration.

---

## Future Development

Possible improvements include:

- Implement T1110.003 Password Spraying detection.
- Add additional MITRE ATT&CK techniques.
- Improve detection correlation between multiple telemetry sources.
- Add automated risk scoring.
- Reduce false positives through behavioral baselining.
- Add automated response workflows.
- Integrate threat intelligence feeds.
- Add additional Splunk dashboards.
- Expand the system to support real-time SOC environments.
- Evaluate the detection logic on additional datasets.

---

## Academic Context

This project was developed as a graduation thesis in the field of **Information Security**.

The research focuses on applying SIEM, automation, and the MITRE ATT&CK framework to build a practical SOC-oriented security detection workflow.

---

## Disclaimer

This project is intended for:

- Educational purposes
- Cybersecurity research
- SOC training
- Defensive security experimentation

The BOTSv3 dataset and detection results are used within a controlled security analysis environment.


---

If you find this project useful for SOC research or cybersecurity learning, feel free to explore the detection modules and extend the existing use cases.
