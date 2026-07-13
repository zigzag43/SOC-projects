password= infected_20210106
## 1. Investigation Overview

|Field|Details|
|---|---|
|Investigation Type|Network Traffic / PCAP Analysis|
|Internal Host|10.1.6.206|
|Suspicious External IP|5.2.136.90|
|Domain|seo.udaipurkart.com|
|Port|80|
|Protocol|HTTP|
|URL Path|`/rx-5700-6hnr7/Sgms/`|
|Downloaded File Name|nDUrg8uFD5hl.dll|
|URL / Extracted Name|Sgms|
|Detection Result|Flagged as malicious in VirusTotal|
|Status|Suspicious activity confirmed from packet analysis|

![[Pasted image 20260709155250.png]]

---

## 2. Initial Finding
![[Pasted image 20260709155250.png]]
During packet capture analysis, I found that internal host **10.1.6.206** was communicating with external IP address **5.2.136.90**.

This IP had high number of packets using **port 80**. Port 80 is used for HTTP web traffic. HTTP is not secure because traffic is not encrypted.

Because the traffic was using HTTP and connected to suspicious external IP, I investigated it further.

---

## 3. HTTP GET Request Analysis

![[Pasted image 20260709155405.png]]
I filtered the packet capture for **HTTP GET requests**.

A GET request means the client is requesting page, file, or resource from web server.

In the TCP stream, I found this request:

```
GET /rx-5700-6hnr7/Sgms/ HTTP/1.1
Host: seo.udaipurkart.com
Connection: Keep-Alive
```

This shows that internal host requested a resource from domain **seo.udaipurkart.com**.

---

## 4. TCP Stream Evidence

![[Pasted image 20260709155433.png]]

![[Pasted image 20260709155506.png]]

The server responded with successful response:

```
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="nDUrg8uFD5hl.dll"
Content-Type: application/octet-stream
```

This means the file download was successful.

|Evidence|Meaning|
|---|---|
|`HTTP/1.1 200 OK`|Request was successful|
|`Content-Disposition: attachment`|Server sent file as download|
|`filename="nDUrg8uFD5hl.dll"`|Actual downloaded file name|
|`Content-Type: application/octet-stream`|Binary file was downloaded|
|`Host: seo.udaipurkart.com`|Source domain of download|

---

## 5. File Name Explanation

![[{E398E1C8-F911-487A-9153-1872D3109C37}.png]]

The extracted or URL name appeared as:

```
Sgms
```

But TCP stream showed actual downloaded file name as:

```
nDUrg8uFD5hl.dll
```

This happened because **Sgms** was part of URL path:

```
/rx-5700-6hnr7/Sgms/
```

But the server gave file name using this header:

```
Content-Disposition: attachment; filename="nDUrg8uFD5hl.dll"
```

So, **Sgms** is the requested path or extracted object name, and **nDUrg8uFD5hl.dll** is the actual file name sent by server.

---

## 6. File Extraction and VirusTotal Check

![[{760D5D8F-46B5-4F39-BE21-5C662854FD70}.png]]

After identifying the download in TCP stream, I extracted the downloaded object from packet capture.

Then I uploaded the extracted file to **VirusTotal**. The result showed that the file was flagged as malicious.

This confirms that the downloaded file was suspicious and likely malware.

Looking at the contacted ip i found the ip same 5.2.136.90 with which the host 10.1.6.206 was communicating too. 

![[{5D9E0B58-11C8-49B1-B5D5-449D45188270}.png]]

![[{789C3848-F805-4532-9E8F-D621784C8F04}.png]]

---

## 7. Multiple POST Requests

During further packet analysis, I found many **POST requests** going to same suspicious IP address **5.2.136.90**.

POST request means client is sending data to server. This is more suspicious because the host is not only downloading file. It is also sending data back to external server.

One TCP stream showed this POST request:

```
POST /7u0e9j2avwlvnuynyo/szcm27k/fzb067wy/ HTTP/1.1
Host: 5.2.136.90
Content-Type: multipart/form-data
Content-Length: 6084
```

This shows that internal host sent data to **5.2.136.90**.

The request also included binary file-like data:

```
Content-Disposition: form-data; name="RPWwLuQoJPkfGpWKw"; filename="iVOwebWBCLKvFqxScD"
Content-Type: application/octet-stream
```

This is suspicious because **application/octet-stream** means raw binary data. The URL path, form name, and filename are also random-looking. Malware often uses random names like this for communication. The POST traffic may indicate possible data exfiltration.

![[{8C14E076-27F9-4E85-B383-DDE357479EAC}.png]]

![[{0CB92DFF-7E5A-4F6F-A7B8-A2452F6A0B94}.png]]


## 8. IOC Table

| IOC Type             | IOC Value              | Description                              |
| -------------------- | ---------------------- | ---------------------------------------- |
| Internal IP          | 10.1.6.206             | Host that downloaded suspicious file     |
| External IP          | 5.2.136.90             | Suspicious IP contacted by internal host |
| Domain               | seo.udaipurkart.com    | Domain used to serve the file            |
| URL Path             | `/rx-5700-6hnr7/Sgms/` | Requested HTTP path                      |
| Port                 | 80                     | HTTP port used                           |
| Protocol             | HTTP                   | Unencrypted web traffic                  |
| HTTP Method          | GET                    | Method used to request the file          |
| HTTP Status          | 200 OK                 | Download was successful                  |
| Downloaded File Name | nDUrg8uFD5hl.dll       | File name given by server                |
| URL / Extracted Name | Sgms                   | Name seen in URL path or extraction      |
| Detection Result     | Malicious / Flagged    | File was detected as malicious           |

---

## 9. Analysis Summary

| Question                    | Answer                                                                       |
| --------------------------- | ---------------------------------------------------------------------------- |
| Was file downloaded?        | Yes, TCP stream shows successful file download.                              |
| Was HTTP used?              | Yes, port 80 HTTP was used.                                                  |
| Was download successful?    | Yes, server returned `200 OK`.                                               |
| Was file suspicious?        | Yes, it was DLL file and VirusTotal flagged it.                              |
| Is this activity malicious? | Very likely malicious based on file reputation and suspicious HTTP download. |

---

## 10. Conclusion

There was no alert generated for this activity. However, packet capture analysis showed suspicious communication between internal host **10.1.6.206** and external IP **5.2.136.90** over HTTP port **80**.

The TCP stream confirmed that host requested:

```
/rx-5700-6hnr7/Sgms/
```

The server responded with **200 OK** and sent a file named:

```
nDUrg8uFD5hl.dll
```

The file was binary type, shown by:

```
Content-Type: application/octet-stream
```

After extraction, the file was uploaded to VirusTotal and was flagged as malicious. Based on this evidence, this is suspicious HTTP file download and possible malware delivery.

---

## 11. Recommended Actions

|Action Type|Action|
|---|---|
|Containment|Isolate host **10.1.6.206** from network.|
|Blocking|Block IP **5.2.136.90** and domain **seo.udaipurkart.com**.|
|Eradication|Remove file **nDUrg8uFD5hl.dll / Sgms** from system.|
|Scanning|Run full antivirus or EDR scan on host.|
|Recovery|Reimage host if malware execution is confirmed.|
|Monitoring|Monitor for more HTTP traffic to same IP or domain.|
|Extra Notes|Check endpoint logs to see if DLL file was executed.|

# 12.Suricata Rules

```
alert http any any -> 5.2.136.90 80 (msg:"Suspicious HTTP traffic to malicious IP 5.2.136.90"; flow:to_server,established; sid:1000001; rev:1;)
```

**Meaning:**  
This rule alerts when any internal host connects to **5.2.136.90** on HTTP port **80**.

## Rule for malicious download domain

```
alert http any any -> any 80 (msg:"Suspicious HTTP request to seo.udaipurkart.com"; flow:to_server,established; http.host; content:"seo.udaipurkart.com"; nocase; sid:1000002; rev:1;)
```

**Meaning:**  
This rule alerts when HTTP request goes to domain **seo.udaipurkart.com**.

## Create SHA256 hash list file

Create file:

```
/etc/suricata/rules/sha256-malware.list
```

Add this hash inside it:

```
8e37a82ff94c03a5be3f9dd76b9dfc335a0f70efc0d8fd3dca9ca34dd287de1b
```

## 2. Suricata rule

Add this rule in your local rules file:

```
alert http any any -> any any (msg:"Malicious file download SHA256 match nDUrg8uFD5hl.dll"; flow:established; filesha256:sha256-malware.list; classtype:trojan-activity; sid:1000011; rev:1;)
```


ZEEK

![[{EFAB95AE-B4D1-4050-81DA-F26781D5E630}.png]]