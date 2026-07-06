# 1. Alert Overview

| Field                 | Details                                       |
| --------------------- | --------------------------------------------- |
| Alert Name            | SOC335 - CVE-2024-49138 Exploitation Detected |
| Severity              | Medium                                        |
| Event ID              | 313                                           |
| Alert Type            | Privilege escalation attack                   |
| Source IP / Host      | 185.107.56.141                                |
| Destination IP / Host | 172.16.17.207                                 |
| Target Service        | Windows Common Log File System (CLFS) Driver  |
| Timestamp             | Jan, 22, 2025, 02:37 AM                       |

---

# 2. Initial Assessment

**Main Question:**  
Is this activity normal or suspicious?
Yes This is suspicious because `svohost.exe` looks like fake name similar to legitimate Windows process `svchost.exe`.

| Question                                                                                                                  | Answer                                                  |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| What activity triggered the alert?                                                                                        | execution of this "svohost.exe" file tiggered the alert |
| Is this activity expected or unusual for this user, host, or service?                                                     | unusual                                                 |
| Is there any sign of malicious activity, such as external IP, suspicious command, file creation, or known attack pattern? | yes                                                     |

**Initial Finding:**
In the frist place the Attacker was doing RDP bruteforce attack to access the victim pc.
![[Pasted image 20260704102419.png]]

Success full  remote login from ip address 185.107.56.141 before the alert :

![[{B1394D58-57CA-4A7B-A5C5-21E2BB24312C}.png]]

The File hash flagged it as malicious trojan file. 
![[{270BB53D-2666-4BF9-9B81-547DD80E7594}.png]]


![[{210C1462-8CFB-4B05-9D8D-14904684762A}.png]]

This command downloads password-protected archive from external S3 storage, extracts it using 7-Zip, removes original ZIP file, and executes suspicious binary named `svohost.exe`. This behavior indicates possible malware delivery and execution.

here we can see whoami command was executed from the svohost.exe parent process 
![[Pasted image 20260704100634.png]]


---

# 3. Investigation Steps

## A. Endpoint Evidence

| Area Checked               | Finding                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Process Tree               | RDP Login from 185.107.56.141<br>└── powershell.exe<br>    ├── Invoke-WebRequest<br>    │   └── Downloaded: service-installer.zip<br>    ├── 7z.exe<br>    │   └── Extracted ZIP using password "infected"<br>    ├── Remove-Item<br>    │   └── Deleted service-installer.zip<br>    └── svohost.exe<br>        └── whoami.exe |
| Parent Process             | Powershell                                                                                                                                                                                                                                                                                                                      |
| Command Line               | <br>\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                                                                                                                                                                                                                                     |
| File Created or Downloaded | Downloaded                                                                                                                                                                                                                                                                                                                      |


---

## B. Network Evidence

| Area Checked           | Finding                                                             |
| ---------------------- | ------------------------------------------------------------------- |
| Source and Destination |                                                                     |
| Target URL / Endpoint  | 'https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip' |
| Request Method         | GET                                                                 |
| External IP / Domain   | files-ld.s3.us-east-2.amazonaws.com                                 |


---

# 4. Indicators of Compromise

| IOC Type         | Value                                                                |
| ---------------- | -------------------------------------------------------------------- |
| File Name / Path | <br>"C:\temp\service_installer\svohost.exe"                          |
| File Hash        | <br>b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9 |
| Process Name     | Powershell                                                           |
| User Account     | Victor                                                               |

---

# 5. MITRE ATT&CK Mapping

| Tactic            | Technique                                                                     | Technique ID |
| ----------------- | ----------------------------------------------------------------------------- | ------------ |
| Initial Access    | External Remote Services: RDP successful login after brute force              | T1133        |
| Execution         | PowerShell command execution and malicious file execution                     | T1059.001    |
| Persistence       | Possible Windows Service installation by `service_installer` / `svohost.exe`  | T1543.003    |
| Credential Access | Brute Force against RDP login                                                 | T1110        |
| Defense Evasion   | Masquerading as similar Windows process name `svohost.exe` like `svchost.exe` | T1036        |


---

# 6. Impact Assessment

| Impact Area                         | Status / Details                                                                                                                                                                                                                                                                   |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Was access successful?              | yes                                                                                                                                                                                                                                                                                |
| Was command execution seen?         | yse                                                                                                                                                                                                                                                                                |
| Was any file created or downloaded? | yes                                                                                                                                                                                                                                                                                |
| Is the host compromised?            | yes                                                                                                                                                                                                                                                                                |
| Business Impact                     | The attacker successfully accessed victim PC through RDP and executed malicious Trojan payload. This can lead to data theft, credential compromise, system takeover, business downtime, financial loss, and compliance risk. Immediate containment and investigation are required. |

---

# 7. Final Verdict

True Positive 

Based on the evidence, this alert is confirmed as **true positive malicious activity**.
The attacker first performed **RDP brute-force attempts** against the victim machine. After multiple login attempts, there was a **successful remote login** from external IP address **185.107.56.141** before the alert was triggered. This indicates that the attacker likely gained initial access through exposed RDP service using valid or guessed credentials.

After gaining access, the attacker executed a PowerShell command that downloaded a password-protected ZIP file from external S3 storage. The archive was extracted using 7-Zip with password **`infected`**, then the original ZIP file was deleted. After extraction, a suspicious executable named **`svohost.exe`** was started from the extracted folder.

The file name **`svohost.exe`** is suspicious because it looks similar to legitimate Windows process **`svchost.exe`**, which is common masquerading technique used by malware. The file hash was also flagged as **malicious Trojan**, which supports that this executable is not legitimate.

Further evidence shows that **`whoami`** command was executed with **`svohost.exe` as parent process**. This is strong sign of attacker activity because `whoami` is commonly used after compromise to check current user privilege and confirm what account the malware or attacker is running as.



---

# 8. Recommended Actions

| Action Type | Action                                                                                                                                                                                  |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Containment | Isolate victim PC from network. Block external IP `185.107.56.141` and S3 download URL. Disable affected user account and reset password.                                               |
| Eradication | Remove `C:\temp\service_installer\svohost.exe` and related files. Kill suspicious process. Run full AV/EDR scan. Check and remove any service, scheduled task, or registry persistence. |
| Recovery    | Restore system from clean backup or rebuild host if compromise is high. Patch Windows. Re-enable device only after clean scan and validation.                                           |
| Monitoring  | Monitor RDP login attempts, failed logins, PowerShell download activity, `7z.exe` extraction, and execution from `C:\temp` or `AppData`                                                 |
| Extra Notes | Treat host as compromised. Check other systems for same IP, same hash, same URL, and `svohost.exe`. Enable MFA and restrict RDP access by VPN or allowlist.                             |
