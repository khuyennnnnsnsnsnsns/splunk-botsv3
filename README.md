# splunk-botsv3-threat-hunting

# 📖 Description
This project implements a comprehensive log analysis and threat detection system built on Splunk Enterprise Free for security monitoring and incident investigation. The system leverages the BOTS v3 (Boss of the SOC) dataset—a realistic cyber attack simulation developed by Splunk—to demonstrate practical security analytics capabilities in a controlled environment.

## Core Capabilities
Centralized Log Management — Aggregates and normalizes log data from multiple sources including AWS CloudTrail, Office 365, Sysmon, and Zeek

Threat Detection — Implements 7+ detection use cases covering the complete cyber attack lifecycle

MITRE ATT&CK Integration — Maps detected threats to industry-standard tactics and techniques (T1046, T1110, T1136, T1068, T1003.001, T1071, T1021)

Interactive Dashboards — Provides visual representations of security metrics and attack patterns

Incident Investigation — Simulates professional SOC analyst workflows from detection through remediation

## Key Features

Feature	Description

SIEM Platform	Splunk Enterprise Free (Single-Instance)

Attack Dataset	BOTS v3 (320 MB, pre-indexed)

Detection Use Cases	7+ rules covering Reconnaissance, Brute Force, Persistence, Privilege Escalation, Credential Dumping, C2, and Lateral Movement

Threat Intelligence	MITRE ATT&CK Framework v15

Query Language	SPL (Search Processing Language)

Visualization	Custom Dashboards & Reports

# 🏗️ System Architecture
# Overview
The system follows a Single-Instance (S1) Architecture as required by Splunk Enterprise Free limitations. All core components—Indexer, Search Head, and Forwarder—run on a single machine, making it ideal for academic research and proof-of-concept deployments.

# Architecture Diagram
<pre>
┌──────────────────────────────────────────────────────────────────────────────┐
│                         DATA SOURCE LAYER                                   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      BOTS v3 DATASET                                │   │
│   │                                                                     │   │
│   └─────────────────────────────┬───────────────────────────────────────┘   │
│                                  │                                          │
│                                  ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      SPLUNK APP BOTS v3                             │   │
│   └─────────────────────────────┬───────────────────────────────────────┘   │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     SPLUNK ENTERPRISE                                        │
│                                                                              │
│                                                                              │
│    ┌─────────────────────┐          ┌───────────────────────────────────┐    │
│    │      INDEXER        │◄────────►│           SEARCH HEAD             │    │
│    │  Data Processing &  │          │    SPL Execution & Web UI         │    │
│    │    Storage          │          │                                   │    │
│    └─────────────────────┘          └───────────────┬───────────────────┘    │
│                                                      │                       │
└──────────────────────────────────────────────────────┼───────────────────────┘
                                                       │
                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                  THREAT DETECTION & MITRE ATT&CK MAPPING                     │
│                                                                              │
│   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌─────────┐    │
│   │  RECONNAISSANCE│  │    BRUTE      │   │  PERSISTENCE  │   │   C2    │    │
│   │  (T1046)      │   │  FORCE (T1110)│   │  (T1136)      │   │ (T1071) │    │
│   └───────────────┘   └───────────────┘   └───────────────┘   └─────────┘    │
│                                                                              │
│   ┌───────────────┐   ┌───────────────┐   ┌─────────────────────────────┐    │
│   │   PRIVILEGE   │   │    LSASS      │   │   LATERAL MOVEMENT          │    │
│   │  ESCALATION   │   │  (T1003.001)  │   │   (T1021)                   │    │
│   │  (T1068)      │   │               │   │                             │    │
│   └───────────────┘   └───────────────┘   └─────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────┘
                                                       │
                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            OUTPUT LAYER                                      │
│                                                                              │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────────┐    │
│   │    DASHBOARD    │   │    REPORTS      │   │   MITRE MAPPING TABLE   │    │
│   └─────────────────┘   └─────────────────┘   └─────────────────────────┘    │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │                   ADMIN / USER (Security Analyst)                   │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────┘
</pre>
# Component Breakdown

Component	Role	Description

BOTS v3 Dataset	Data Source	Pre-indexed dataset simulating multi-stage APT attacks in hybrid cloud environments

Splunk App BOTS v3	Application	Packages dataset and configurations for seamless deployment

Splunk Enterprise (Free)	Core Platform	SIEM platform with 500 MB/day ingestion limit

Indexer	Processing Engine	Processes, indexes, and stores log data for fast retrieval

Search Head	User Interface	Provides web interface for SPL queries and visualization

MITRE Mapping	Analytical Layer	Maps detections to MITRE ATT&CK Framework

Dashboard/Reports	Output	Visual representations of security findings

# Technical Specifications

Specification	Minimum	Recommended

Architecture	Single-Instance	Single-Instance

Splunk Version	9.0+	9.2+

OS	Linux/Windows	Rocky Linux 9

RAM	8 GB	12 GB

CPU	4 cores	8 cores

Storage	20 GB	100 GB+

Ingestion Limit	500 MB/day	N/A

# Data Flow

Ingestion — BOTS v3 dataset installed as Splunk App (bypasses 500 MB/day limit)

Processing — Indexer processes and stores data

Analysis — Security analyst runs SPL queries for threat detection

Mapping — Detected events mapped to MITRE ATT&CK

Visualization — Results displayed in dashboards and reports

Investigation — Complete incident response workflow simulation

# 💻 Skills & Technologies
## Technical Skills

Category	Skills

SIEM Platforms	Splunk Enterprise (Installation, Configuration, Administration)

Query Languages	SPL (Search Processing Language)

Threat Intelligence	MITRE ATT&CK Framework

Security Analysis	Log Analysis, Threat Hunting, Incident Investigation

Data Analytics	Statistical Analysis, Pattern Recognition, Anomaly Detection

Visualization	Dashboard Design, Report Generation

# Security Domains Covered

Domain	Description

SOC Operations	Security Operations Center workflows and procedures

Incident Response	Detection, investigation, and remediation processes

Threat Detection	Use case development and implementation

Log Management	Aggregation, normalization, and analysis

Cloud Security	AWS CloudTrail and Office 365 log analysis

Endpoint Security	Sysmon and Windows Event Log analysis

Network Security	Zeek network traffic analysis

## Tools & Technologies

Tool/Technology	Purpose

Splunk Enterprise 9.2+	Core SIEM platform

SPL	Search and analysis queries

BOTS v3	Attack simulation dataset

MITRE ATT&CK	Threat intelligence framework

Rocky Linux 9	Operating system

Docker	Optional containerization

## Knowledge Areas

✅ Security Information and Event Management (SIEM)

✅ Cyber Attack Lifecycle & Kill Chain

✅ Log Analysis & Forensics

✅ Threat Intelligence & Contextualization

✅ Security Monitoring & Alerting

✅ Incident Response Procedures

✅ Cloud Security Monitoring

✅ Network Traffic Analysis

# 📁 Project Structure
<pre>
splunk-botsv3-analysis/
├── README.md                    # Project documentation
├── LICENSE                      # MIT License
├── .gitignore                   # Git ignore rules
├── docs/
│   ├── diagrams/                # Architecture diagrams
│   │   ├── architecture.png
│   │   └── mitre_mapping.png
│   └── report/                  # Thesis documentation
│       ├── thesis_vietnamese.pdf
│       └── thesis_english.pdf
├── splunk/
│   ├── queries/                 # SPL query library
│   │   ├── 01_reconnaissance.md
│   │   ├── 02_brute_force.md
│   │   ├── 03_persistence.md
│   │   ├── 04_privilege_escalation.md
│   │   ├── 05_credential_dumping.md
│   │   ├── 06_command_and_control.md
│   │   └── 07_lateral_movement.md
│   ├── dashboards/              # Dashboard configurations
│   │   └── dashboard_config.xml
│   └── addons/                  # Required Splunk Add-ons
│       └── addon_list.txt
├── results/                     # Analysis outputs
│   ├── findings.csv
│   ├── statistics.md
│   └── incident_case_study.md
└── scripts/                     # Automation scripts
    ├── install_splunk.sh
    └── load_bots_data.sh
</pre>

# 🔧 MITRE ATT&CK Use Cases
#	Tactic	Technique	ID	Query Focus

1	Reconnaissance	Network Service Scanning	T1046	Port scanning detection

2	Credential Access	Brute Force	T1110	Failed login analysis

3	Persistence	Create Account	T1136	New user account detection

4	Privilege Escalation	Exploitation for Privilege Escalation	T1068	Privilege escalation detection

5	Credential Access	OS Credential Dumping	T1003.001	LSASS process access

6	Command & Control	Application Layer Protocol	T1071	DNS tunneling detection

7	Lateral Movement	Remote Services	T1021	Cross-segment movement detection

