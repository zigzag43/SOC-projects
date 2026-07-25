
# 1. Investigation Overview

> This report investigates website attack against `imreallynotbatman.com` using BOTSv1 logs in Splunk. Investigation covers vulnerability scanning, brute-force login, PHP backdoor upload, malicious file execution, post-exploitation activity, and website defacement.

# 2. Finding BOTSv1 Index

![[Pasted image 20260721093932.png]]

> First, I searched available indexes in Splunk. I found `botsv1` index and selected it for investigation.

Query:

```
| eventcount summarize=false
| dedup index
| fields index
```
![Copy](data:image/svg+xml,%EF%BB%BF%3Csvg%20width%3D%2218%22%20height%3D%2219%22%20viewBox%3D%220%200%2018%2019%22%20fill%3D%22none%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0D%0A%20%20%20%20%3Cpath%20d%3D%22M4.11363%203.54174L4.11153%205.16645V13.2054C4.11153%2014.579%205.19925%2015.6926%206.54102%2015.6926L12.982%2015.6929C12.751%2016.3615%2012.1281%2016.8406%2011.3958%2016.8406H6.54102C4.57998%2016.8406%202.99023%2015.2131%202.99023%2013.2054V5.16645C2.99023%204.41591%203.45927%203.77752%204.11363%203.54174ZM13.2688%201.53125C14.1977%201.53125%2014.9508%202.30219%2014.9508%203.25319V13.2022C14.9508%2014.1531%2014.1977%2014.9241%2013.2688%2014.9241H6.54102C5.6121%2014.9241%204.85907%2014.1531%204.85907%2013.2022V3.25319C4.85907%202.30219%205.6121%201.53125%206.54102%201.53125H13.2688ZM13.2688%202.67921H6.54102C6.23138%202.67921%205.98037%202.93619%205.98037%203.25319V13.2022C5.98037%2013.5192%206.23138%2013.7761%206.54102%2013.7761H13.2688C13.5784%2013.7761%2013.8295%2013.5192%2013.8295%2013.2022V3.25319C13.8295%202.93619%2013.5784%202.67921%2013.2688%202.67921Z%22%20fill%3D%22%23767676%22%20%2F%3E%0D%0A%3C%2Fsvg%3E)

- **_eventcount summarize=false_** ensures you get actual index names instead of summarized counts.
    
- **_dedup index_** removes duplicates.
    
- **_fields index_** displays only the index column. This will return every index your role has permission to search

# 3. Identifying Available Log Sources


![[{721D0C2B-2B68-4F57-8BC0-C12468057D2A}.png]]

I checked available sourcetypes to understand which security logs were collected. The dataset contained Suricata, HTTP stream, Windows Security, Sysmon, and FortiGate logs.

# 4. Finding Suspicious Web Traffic


![[{B677BDE1-4DF3-4975-8448-A0C0945D5B80}.png]]

I started with Suricata logs and checked destination ports. Port `80` had high traffic, which showed large amount of HTTP communication.

## 4.2 Suspicious Source IP

![[Pasted image 20260721100411.png]]

The attacker first scanned `imreallynotbatman.com` to find possible vulnerabilities.

The highest traffic was from source IP address `40.80.148.42`. I added this IP address to the search:

```
index="botsv1" sourcetype=suricata dest_port=80 src_ip="40.80.148.42"
```

After checking the `http.hostname` field, I found that most traffic was sent to:

```
imreallynotbatman.com
```


![[{DF4C1A1F-349D-4836-95E1-4221A3AF04FC}.png]]

Then I checked the `http.url` field. Most requests were sent to Joomla search pages.

![[{0F68CA54-136F-4F87-9742-3490F0B825DC}.png]]

I also found that most requests were HTTP POST requests.

![[Pasted image 20260721101723.png]]

To inspect the POST requests in more detail, I changed the source to HTTP stream logs:

```
index="botsv1" src_ip="40.80.148.42"
source="stream:http"
http_method=POST
imreallynotbatman.com
```

The raw HTTP header showed:

```
Acunetix Web Vulnerability Scanner - Free Edition
```

This shows that Acunetix was used to scan website for vulnerabilities such as SQL injection and other web weaknesses.

![[{449E4772-F8A3-47F7-84F2-9ACDA4B6B8C9} 1.png]]


# 5. Finding How the Attacker Entered the System

Now, it was important to find whether attacker was able to get into the system and how . To investigate this, I checked HTTP POST requests containing username and password fields. The attacker attempted to log in to Joomla administrator account using username `admin` and password `batman` and was successfully logged in.
 ![[{2BE5EC43-40AB-4FD5-8BB4-4385DD57C8E8}.png]]

To find out how attacker got the password, I filtered the logs for two minutes before the successful login activity. I found that another IP address, `23.22.63.114`, sent many POST requests to same login page using username `admin` with different passwords. This repeated login activity strongly indicates a brute-force attack.

The query used was:

```
index="botsv1" source="stream:http" http_method=POST imreallynotbatman.com form_data="*username=admin*"
| table _time, form_data, src_ip
| sort _time
```

The attacker continued trying different passwords.

![[{EB81196F-5B54-4025-9E1C-8795D49231D8}.png]]


# 6. Uploading the PHP Backdoor

After the successful login activity, attacker uploaded a PHP file named:

```
agent.php
```

The HTTP multipart request showed the filename and obfuscated PHP code.

![[{6027452D-9C61-411C-9245-8F7813D8E16D}.png]]

The file was likely a PHP backdoor. A backdoor allows attacker to send commands to server after getting access.

To investigate further, I searched for requests related to `agent.php`:

```
index="botsv1"
source="stream:http"
http_method=POST
imreallynotbatman.com
agent.php
| sort _time
```

The later logs showed that another file named `3791.exe` was also transferred to server.

![[{BC32716C-33E5-4F6A-ACBC-6A24EE79435E}.png]]

# 7. Confirming Execution of 3791.exe

The HTTP logs showed that `3791.exe` was transferred, but it was necessary to confirm whether file was executed.

I checked Windows Sysmon logs and identified victim hostname as:

```
we1149srv
```

![[{F34A46B7-771A-4C2B-9C03-90BEFF902C26}.png]]

I then searched Sysmon process creation events for `3791.exe`

query:

```
index="botsv1" host="we1149srv"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]ParentImage['\"]>(?<ParentImage>[^<]+)</Data>"
| search Image="*3791.exe*" OR CommandLine="*3791.exe*"
| table _time Image CommandLine ParentImage
| sort _time
```

The Sysmon event confirmed that `3791.exe` was executed on server.

![[{0EFECA6B-FE11-4A72-87DD-16480DCCB63F}.png]]

This confirms that executable was not only transferred but also started on compromised host.

## 8. Post-Exploitation Discovery

After gaining command execution, attacker started collecting information from server and network.

The logs showed commands such as:

```
whoami
net user
net view /domain
net share
net session
```

These commands were used for following purposes:

- `whoami` identified current user.
- `net user` listed available user accounts.
- `net view /domain` searched domain systems.
- `net share` listed shared folders.
- `net session` checked active network sessions and possible administrative access.

![[{C3A91567-64D7-4DB3-AC06-0E40AA8AD0AC}.png]]

This was post-exploitation discovery activity. The attacker was learning about compromised environment before performing next actions.

There is no direct evidence that privilege escalation was successfully performed. The commands mainly show information gathering and privilege checking.

## 9. Investigating the Purpose of 3791.exe

To get more information about `3791.exe`, I extracted its MD5 hash from Sysmon logs.

The MD5 hash was:

```
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

![[{3670376E-E93E-4E62-9272-66988F1D6871}.png]]

I searched this hash in VirusTotal. In behaviour information, I found communication related to IP address:

```
23.22.63.114
```

This was same IP address connected with earlier brute-force activity.

![[{F2795433-5760-4964-B6C6-740E39583F39}.png]]

This provided supporting evidence that `3791.exe` was related to attacker activity.

## 10. Finding Outbound Communication

After finding this IP address in VirusTotal, I checked whether compromised host communicated with it.

The query was:

```
index="botsv1"
src_ip="192.168.250.70"
dest_ip="23.22.63.114"
```

The results showed that compromised host contacted:

```
prankglassinebracket.jumpingcrab.com
```

The communication used destination port:

```
1337
```

The requested URL was:

```
/poisonivy-is-coming-for-you-batman.jpeg
```



FortiGate also classified the domain as:

```
Malicious Websites
```

The important fields were:

```
srcip=192.168.250.70
dstip=23.22.63.114
dstport=1337
hostname=prankglassinebracket.jumpingcrab.com
url=/poisonivy-is-coming-for-you-batman.jpeg
```

**Place image here:** FortiGate screenshot showing port 1337 and malicious website category.

The host made HTTP GET requests to retrieve this file.

![[Pasted image 20260725035319.png]]

The HTTP response contained valid JPEG information such as:

```
Exif
Adobe Photoshop CS6
ICC_PROFILE
```

The response also contained around `554068` bytes of data. This confirms that server received a real JPEG file.

![[26c0e190-379f-47cc-9caf-a2e5d885a2b4.png]]

This communication may have supported attacker control and file retrieval. However, available logs directly confirm the communication and JPEG transfer, not every function of the communication.


## 11. Preparing the Defacement Image

Shortly after the JPEG retrieval, commands executed through `php-cgi.exe` changed image filenames.

The commands were:

```
move ..\1.jpeg 2.jpeg
move 2.jpeg imnotbatman.jpg
```

![[{040D7924-4720-4ED9-8C4D-ADFD0F98F1A1}.png]]

This shows following file movement:

```
1.jpeg
   ↓
2.jpeg
   ↓
imnotbatman.jpg
```

The parent process was:

```
C:\Program Files (x86)\PHP\v5.5\php-cgi.exe
```

This means attacker executed the commands through PHP backdoor or web shell.

![[{7726B310-DEA4-4AB4-8B73-7846B3FBB0AC}.png]]

The compromised host retrieved `poisonivy-is-coming-for-you-batman.jpeg` from the attacker-controlled domain `prankglassinebracket.jumpingcrab.com` over port `1337`. HTTP stream data confirmed that response contained valid JPEG content. Shortly afterward, commands executed through `php-cgi.exe` renamed `1.jpeg` to `2.jpeg` and then renamed `2.jpeg` to `imnotbatman.jpg`. Based on close timing, related JPEG file manipulation, and BOTSv1 challenge evidence, the downloaded image was used for website defacement. 

## 12. Cyber Kill Chain Summary

| Stage                 | Evidence                                                                    |
| --------------------- | --------------------------------------------------------------------------- |
| Reconnaissance        | Acunetix scanned `imreallynotbatman.com`                                    |
| Weaponization         | `agent.php` and `3791.exe` were prepared                                    |
| Delivery              | Malicious files were transferred through HTTP POST requests                 |
| Exploitation          | Repeated password attempts were made until attacker continued inside system |
| Installation          | `agent.php` backdoor was uploaded and `3791.exe` was executed               |
| Command and Control   | Compromised host communicated with `23.22.63.114` and malicious domain      |
| Actions on Objectives | Attacker performed discovery and prepared image for website defacement      |

