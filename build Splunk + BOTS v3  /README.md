# Splunk Enterprise + BOTS v3 Setup Guide

## Overview

This project demonstrates how to install **Splunk Enterprise** on Kali Linux (or other Debian-based distributions) and deploy the **Boss of the SOC (BOTS) v3** dataset for security monitoring, threat hunting, and SOC practice.

The BOTS v3 dataset is a pre-indexed Splunk dataset containing realistic security events collected from Windows, Linux, web servers, network devices, cloud services, and various security tools. Because it is distributed as a **pre-indexed Splunk App**, it can be installed directly without consuming Splunk indexing license volume.

---

# Lab Environment

| Component         | Version    |
| ----------------- | ---------- |
| OS                | Kali Linux |
| Splunk Enterprise | 8.2.6      |
| Dataset           | BOTS v3    |

---

# Download Splunk Enterprise

Download Splunk Enterprise:

```bash
wget -O splunk-8.2.6-a6fe1ee8894b-linux-2.6-amd64.deb \
"https://download.splunk.com/products/splunk/releases/8.2.6/linux/splunk-8.2.6-a6fe1ee8894b-linux-2.6-amd64.deb"
```

Reference:

* Splunk download script: https://gist.github.com/devops-school/3247238bfdf8a4cbaf6039a1a38ba516

---

# Install Splunk

Install the downloaded package:

```bash
sudo dpkg -i splunk-8.2.6-a6fe1ee8894b-linux-2.6-amd64.deb
```

If dependency errors occur:

```bash
sudo apt --fix-broken install
```

or

```bash
sudo apt install -f
```

---

# Start Splunk

Run Splunk for the first time:

```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

During initialization:

* Accept the license
* Create an administrator account
* Set a password

Enable automatic startup:

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

Check status:

```bash
sudo /opt/splunk/bin/splunk status
```

---

# Access Splunk Web

Open your browser:

```
http://localhost:8000
```

Login using the administrator account created during installation.

---

# Download BOTS v3 Dataset

Official repository:

https://github.com/splunk/botsv3

Clone the repository:

```bash
git clone https://github.com/splunk/botsv3.git
```

Or download the release package:

```
botsv3_data_set.tgz
```

---

# Extract Dataset

Move to the download directory:

```bash
cd ~/Downloads
```

Extract the dataset:

```bash
tar -xzvf botsv3_data_set.tgz
```

The extracted directory should look similar to:

```
botsv3_data_set/
├── bin
├── default
├── lookups
├── var
├── LICENSE
└── README.txt
```

---

# Install BOTS v3

Since BOTS v3 is distributed as a **pre-indexed Splunk App**, do **not** upload it using **Add Data**.

Copy the extracted folder into the Splunk Apps directory:

```bash
sudo cp -r ~/Downloads/botsv3_data_set /opt/splunk/etc/apps/
```

Restart Splunk:

```bash
sudo /opt/splunk/bin/splunk restart
```

After restarting, Splunk automatically recognizes the application and loads the pre-indexed dataset.

---

# Verify Installation

Open Splunk Search & Reporting and execute:

```spl
index=*
```

Count all indexed events:

```spl
| eventcount summarize=false index=*
```

Display event count by index:

```spl
index=* | stats count by index
```

The BOTS v3 dataset should contain approximately **2 million events**, depending on the dataset version.

---

# Useful SPL Queries

## Top Source IP Addresses

```spl
index=* | top src_ip
```

---

## Top Destination IP Addresses

```spl
index=* | top dest_ip
```

---

## Display All Sourcetypes

```spl
index=* | stats count by sourcetype | sort -count
```

---

## Display All Hosts

```spl
index=* | stats count by host
```

---

## Failed Windows Logons

```spl
index=* EventCode=4625
```

---

## Successful Windows Logons

```spl
index=* EventCode=4624
```

---

## Sysmon Process Creation

```spl
index=* EventCode=1
```

---

## Sysmon Network Connections

```spl
index=* EventCode=3
```

---

## Verify Dataset Time Range

```spl
index=*
| stats earliest(_time) as First latest(_time) as Last
| convert ctime(First) ctime(Last)
```

---

# Project Structure

```
/opt/splunk/
└── etc/
    └── apps/
        ├── botsv3_data_set/
        ├── search/
        └── launcher/
```

---

# References

* BOTS v3 Official Repository: https://github.com/splunk/botsv3
* Splunk Enterprise Installation Guide: https://help.splunk.com/
* Splunk Download Script: https://gist.github.com/devops-school/3247238bfdf8a4cbaf6039a1a38ba516
