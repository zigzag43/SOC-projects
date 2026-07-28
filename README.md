<div align="center">

# 🛡️ SOC Projects

### Blue Team Security Operations Center Portfolio

*Real-world investigations in log analysis, alert triage, network forensics, and incident response*

![Blue Team](https://img.shields.io/badge/Focus-Blue%20Team-0057b7?style=for-the-badge&logo=shield&logoColor=white)
![SOC](https://img.shields.io/badge/Domain-SOC%20Analysis-1f6feb?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-2ea043?style=for-the-badge)

</div>

---

## 📖 About This Repository

This repository contains hands-on **Security Operations Center (SOC)** projects, built to demonstrate practical blue team skills in a real analyst workflow.

Each investigation uses tools like **Splunk, Wireshark, Zeek, VirusTotal, LetsDefend**, and raw **PCAP files** to work through detection, investigation, and response — the way it would be handled on a live SOC team.

Every project includes:

- 🔎 Investigation process
- 🧾 Evidence and findings
- 🎯 Attack details and root cause
- 💥 Business impact assessment
- ✅ Recommended remediation actions

> **Goal:** Show practical, evidence-based SOC analysis and blue team thinking — not just theory.

---

## 📂 Projects

<table>
<tr>
<td width="33%" valign="top">

### 🔍 BOTSv1 Investigation

Investigated web attacks and system activity using the Splunk **Boss of the SOC v1** dataset.

**Highlights**
- HTTP GET/POST request analysis
- Brute-force login investigation
- Compromised account identification
- Windows Sysmon log analysis
- Suspicious process execution
- Website defacement investigation
- Malicious IP/domain identification
- Full incident report

**[→ View BOTSv1 Report](./BOTSV1%20Report)**

</td>
<td width="33%" valign="top">

### 🚨 LetsDefend SOC Investigations

Investigated real SOC alerts on the **LetsDefend** platform, end to end.

**Highlights**
- Alert triage
- Source/destination IP analysis
- Process tree investigation
- File hash analysis
- Malware behavior analysis
- MITRE ATT&CK mapping
- Business impact analysis
- Containment & remediation plan

**[→ View LetsDefend Projects](./Letsdefends)**

</td>
<td width="33%" valign="top">

### 🌐 PCAP Analysis

Analyzed raw network traffic to uncover suspicious and malicious activity.

**Highlights**
- DNS traffic analysis
- HTTP request investigation
- Suspicious IP identification
- Malicious domain examination
- Network IOC extraction
- Infected host communication
- C2 traffic investigation

**[→ View PCAP Analysis](./PCAP%20analysis)**

</td>
</tr>
</table>

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|---|---|
| **Splunk** | Log searching and security investigation |
| **Wireshark** | Network packet analysis |
| **Zeek** | Network traffic analysis |
| **LetsDefend** | SOC alert investigation |
| **VirusTotal** | IP, domain, URL, and file hash analysis |
| **CyberChef** | Data decoding and analysis |
| **Kali Linux** | Security testing and investigation |
| **Sysmon** | Windows process and event monitoring |
| **MITRE ATT&CK** | Mapping attacker techniques |
| **GitHub** | Project documentation and version control |

---

## 🔎 Investigation Process

Every project in this repository follows a consistent SOC methodology, from alert to closure:

```text
        🔔 Security Alert
              ↓
        🧭 Initial Assessment
              ↓
        📊 Log & Traffic Analysis
              ↓
        🌐 IP, Domain & File Investigation
              ↓
        🕒 Attack Timeline Creation
              ↓
        🗺️  MITRE ATT&CK Mapping
              ↓
        💼 Business Impact Analysis
              ↓
        🧯 Containment & Remediation
              ↓
        📄 Final Incident Report
```

This structure keeps every investigation consistent, repeatable, and audit-ready — the same standard expected in a production SOC environment.

---

<div align="center">

### 📫 Let's Connect

If you're reviewing this repository for recruitment, collaboration, or feedback — feel free to reach out.

*Built with a focus on defensive security, detection engineering, and real analyst workflows.*

</div>
