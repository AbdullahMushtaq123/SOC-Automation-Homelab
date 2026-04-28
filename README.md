# SOC Automation Homelab Project

## 📝 Executive Summary
This project demonstrates the design, deployment, and configuration of a comprehensive Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) pipeline. Moving beyond basic log aggregation, this architecture automates threat detection, threat intelligence enrichment, and incident ticket creation to effectively reduce alert fatigue and accelerate the incident response lifecycle.

<img width="1443" height="1051" alt="image" src="https://github.com/user-attachments/assets/172c6b4f-3700-483a-8772-0e31a518baaf" />

## 🛠️ Core Technologies
* **Endpoint:** Windows 10 Virtual Machine
* **Telemetry & Forwarding:** Sysmon, Filebeat, Wazuh Agent
* **SIEM:** Wazuh Manager (Dockerized on Ubuntu Server)
* **SOAR:** Shuffle (Cloud)
* **Threat Intelligence:** VirusTotal API (v3)
* **Incident Management:** TheHive (Dockerized on Ubuntu Server, exposed via Ngrok)

---

## 🚀 Phase-by-Phase Execution

### Phase 1: Endpoint Telemetry & Ingestion
The pipeline begins at the endpoint level. Sysmon was installed on the Windows VM to generate deep, OS-level telemetry targeting process creation and memory events. The Wazuh Agent ingests these Sysmon event logs and securely ships them to the central Wazuh Manager. 

Filebeat configurations were tuned within the Docker container to ensure the raw data firehose was successfully mapped to the Wazuh indexer, allocating sufficient virtual memory (`vm.max_map_count=262144`) to prevent out-of-memory errors.

### Phase 2: Custom Detection Engineering
To test the pipeline, `mimikatz.exe` was utilized as the simulated threat payload. Default Wazuh rules were bypassed to engineer a custom XML detection rule, significantly reducing noise and false positives.

By specifically locking the detection to Sysmon Event ID 1 (Process Creation) and utilizing PCRE2 regex, singular, high-fidelity alerts were generated per execution.

**Custom Detection Rule (`local_rules.xml`):**
```xml
<group name="custom_rules, sysmon, mimikatz,">
  <rule id="100002" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>CRITICAL SOC ALERT: Mimikatz credential dumper detected!</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```
### Phase 3: SOAR Integration & Threat Enrichment
A custom Python integration was built to connect the Wazuh Manager to the Shuffle SOAR platform securely.

The Messenger Integration (custom-shuffle.py):

```Python
#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests

# Read the alert file that Wazuh generates
with open(sys.argv[1]) as alert_file:
    alert_json = json.load(alert_file)

# Grab the Shuffle Webhook URL from the configuration
webhook_url = sys.argv[3]

# Fire the JSON alert to Shuffle
headers = {'content-type': 'application/json'}
requests.post(webhook_url, json=alert_json, headers=headers)
```

Upon receiving a Level 12 alert, Shuffle executes an automated playbook:

* **Hash Extraction**: A Regex node extracts the pure SHA256 hash ([a-fA-F0-9]{64}) from the raw Wazuh JSON payload.
* **API Enrichment**: The hash is passed to the VirusTotal API to dynamically retrieve the last_analysis_stats.
* **Logic Gate**: Conditional routing dictates that incident response actions only proceed if the malicious score is greater than 5.

<img width="1090" height="647" alt="image" src="https://github.com/user-attachments/assets/035c33aa-9256-45b2-9c91-558623b3441a" />


### Phase 4: Automated Case Management
To handle incident tracking, TheHive was deployed alongside Wazuh using Docker Compose. Because Shuffle operates in the cloud, an Ngrok secure tunnel was established to allow communication with the local TheHive instance.

When the conditional logic confirms a high-severity threat, Shuffle automatically formats a JSON payload and triggers TheHive’s API to generate a critical incident ticket, populated with exact event details.

Dynamic JSON Payload sent to TheHive:

```JSON
{
  "description": "",
  "flag": false,
  "pap": 2,
  "severity": 3,
  "source": "Wazuh",
  "sourceRef": "$exec.timestamp",
  "status": "New",
  "summary": "SOC Team,\n\nWazuh has detected a highly critical file execution. VirusTotal has confirmed this file is malicious.\n\nIncident Details:\n- Endpoint: $exec.agent.name\n- File Name: $exec.full_log.win.eventdata.originalFileName\n- File Hash: $shuffle_tools_1.group_0.#\n- VirusTotal Malicious Score: $virustotal_v3_1.#.body.data.attributes.last_analysis_stats.malicious\n\nPlease investigate immediately.",
  "tags": ["1003"],
  "title": "Mimikatz Execution Detected - $exec.agent.name",
  "tlp": 2,
  "type": "Malware"
}
```

<img width="1090" height="544" alt="image" src="https://github.com/user-attachments/assets/83960c5c-bf7f-458e-91ce-72b13dd104b1" />

## 🧠 Key Learnings & Proficiencies
* Navigating and modifying Docker-based SIEM deployments.
* Writing custom XML and PCRE2 Regex detection rules to tune SIEM noise.
* Building API-driven SOAR playbooks and parsing complex, nested JSON data structures.
* Troubleshooting cloud-to-local networking boundaries using secure tunneling (Ngrok).
* Resolving API authentication and data-type formatting errors between independent security applications.

## 📁 Repository Contents
* custom_rules/local_rules.xml - Custom Wazuh detection rule for Mimikatz.
* integrations/custom-shuffle.py - Python script to forward Wazuh alerts to Shuffle.
* docker/docker-compose.yml - Deployment file for TheHive, Elasticsearch, and Cassandra.
* Full_Lab_Report.pdf - Comprehensive, step-by-step project documentation.
