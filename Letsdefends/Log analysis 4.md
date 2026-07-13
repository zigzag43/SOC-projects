# 1. Alert Overview

| Field                 | Details                                                    |
| --------------------- | ---------------------------------------------------------- |
| Alert Name            | SOC325 – Unauthorized Cloud Region Access Attempt Detected |
| Severity              | Low                                                        |
| Event ID              | 303                                                        |
| Alert Type            | Brute-Force / Suspicious Login Attempt                     |
| Source IP / Host      | 134.209.145.73                                             |
| Destination IP / Host | 52.15.206.21                                               |
| User Account          | [test@letsdefend.io](mailto:test@letsdefend.io)            |
| Target Service        | Web Login – `/accounts/login`                              |
| Timestamp             | September 24, 2024, 08:21 AM                               |
| Device Action         | Blocked                                                    |

---

# 2. Initial Assessment

**Main Question:**  
Is this activity normal or suspicious?

Yes, this activity is suspicious because an external IP address made multiple login attempts to the `/accounts/login` endpoint using same user account. The login attempts also came from an unauthorized cloud region.

|                                                                             |                                                                                                                                                     |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Question                                                                    | Answer                                                                                                                                              |
| What activity triggered the alert, and which user, host, or IP is involved? | Multiple login attempts from IP address `134.209.145.73` targeted the account `test@letsdefend.io`.                                                 |
| Is this activity expected or unusual for this user, host, or service?       | This activity is unusual because login attempts came from an unsupported cloud region.                                                              |
| Is there any sign of malicious activity or known attack pattern?            | Yes. The source IP was reported as malicious, and repeated login attempts indicate possible credential brute-force or credential-stuffing activity. |

**Initial Finding:**

The external source IP address `134.209.145.73` was flagged as malicious by VirusTotal.

Threat intelligence also reported that the account `test@letsdefend.io` was compromised two days before this alert. This supports possibility that attacker was trying to use stolen credentials.

The login attempts were blocked because they came from an unauthorized cloud region.

![[{1F3C50E5-4385-40BA-A861-7C78A6A64BD4}.png]]
---
![[{C065A35C-D504-46F9-BDD9-181C86CE1BB5}.png]] 

CTI mailed for the test@defend.io being compromised two days before the alert


---

# 3. Indicators of Compromise

| IOC Type            | Value                                |
| ------------------- | ------------------------------------ |
| IP Address          | 134.209.145.73                       |
| User Account        | test                                 |
| Threat Intelligence | User account reported as compromised |

---

# 4. Final Verdict
 
**True Positive – Malicious Login Activity**

The alert is confirmed as true positive because multiple login attempts were made from same malicious external IP address using an account previously reported as compromised.

Although the attempts were blocked due to unsupported cloud region, the activity shows that attacker may possess valid or stolen account credentials.

---

# 5. Recommended Actions

|   |   |
|---|---|
|Action Type|Action|
|Containment|Block source IP `134.209.145.73` and temporarily disable the affected account.|
|Eradication|Reset account password, revoke active sessions, API tokens, and authentication cookies.|
|Recovery|Re-enable the account after confirming password reset and enable multi-factor authentication.|
|Monitoring|Monitor the account for further login attempts, unusual locations, and suspicious activities.|
|Extra Notes|Review authentication logs to confirm whether any login attempt was successful before it was blocked.|

Successfully closed the alert as a True positive 
![[{0045C724-B367-48BF-8DF3-F916CAF5ACB9}.png]]