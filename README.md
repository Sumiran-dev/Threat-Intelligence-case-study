# 🧠 Threat Intelligence Case Study – SOC Investigation Walkthrough

This investigation was conducted in a simulated SOC environment, where I stepped into the role of a cybersecurity analyst responding to alerts from various sources. Each task mirrored real-world incidents and required techniques like OSINT, malware sandboxing, IOC enrichment, and log analysis to uncover attacker infrastructure and malware activity.

This wasn’t just about finding answers — it was about thinking like an analyst under pressure, asking why something happened, not just what.

---

## 1. Strange Beacon to a Suspicious GIF

**📍 Scenario:**  
Our SOC received alerts of multiple internal systems reaching out to [http://45.63.126.199/dot.gif](hxxp://45[.]63[.]126[.]199/dot.gif).  

**🔎 Investigation:**  
I searched this IOC in Gnumeric and uncovered its association with **Cobalt Strike**, a well-known post-exploitation tool used by advanced threat actors.

**✅ Finding:**  
Cobalt Strike beacon activity.

**🧠 Thought Process:**  
This was likely a **payload staging** or **command-and-control (C2)** channel in action.


![image](https://github.com/user-attachments/assets/8d802507-2a9d-43e6-a814-8f6689c96f3e)

Fig: CSV file location

![image](https://github.com/user-attachments/assets/b7361538-5644-43bf-817f-e1f9e0a47e95)

![image](https://github.com/user-attachments/assets/41ee9707-9412-42c8-a916-a459b0edce7b)

![image](https://github.com/user-attachments/assets/07f04896-13b8-4261-9902-1d662e103b65)

Fig: After  searching url: hxxp://45[.]63[.]126[.]199/dot[.]gif, in Gnumeric, I found Cobalt Strike which is related to network connections from 3 internal hosts towards hxxp://45[.]63[.]126[.]199/dot[.]gif

---

## 2. Counting Repeated Beacon Attempts

**📍 Scenario:**  
How many times has the endpoint `dot.gif` appeared in our threat feeds?

**🔧 Investigation:**  
Using CLI tools, I analyzed `full_urls.csv` and other export files. The command-line search revealed **568** instances of this endpoint across the dataset.

**✅ Finding:**  
568 URLs referencing `dot.gif`.

**📌 Insight:**  
This suggests a **widespread campaign**, with repeated attempts from various sources targeting the same endpoint.


![image](https://github.com/user-attachments/assets/f2b5e0a4-578e-44f7-b44b-491a7c862aac)

Fig: Using grep command to find the total number of dot.gif, used by all export files, using Ubuntu CLI

---

## 3. Suspicious File on an Executive’s Android Device

**📍 Scenario:**  
An Android file was quarantined, and we needed to assess its risk level.

**🔍 Investigation:**  
I queried the SHA256 hash `6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5` on [MalwareBazaar](https://bazaar.abuse.ch) and found it linked to **IRATA spyware**, a known mobile surveillance threat.

**✅ Finding:**  
IRATA – a mobile spyware used for unauthorized surveillance.

**💡 Takeaway:**  
Quick hash lookups using trusted platforms like MalwareBazaar can help identify hidden threats and prevent further compromise — especially on executive devices.


![image](https://github.com/user-attachments/assets/4938aa4b-7c78-44b6-aa3e-387e2f96368f)

Fig: Spotting IRATA spyware

---

## 4. Digging Deeper into IRATA

**📍 Scenario:**  
To contain and block the threat, we needed to enrich the IOC details for the IRATA sample.

**🌐 Investigation:**  
Using the reference link provided in the previous hash lookup, I discovered:

- **Threat Name:** IRATA  
- **C2 Domain:** `uklivemy.gq`  
- **IP Address:** `20.238.64.240`  
- **Registrar:** Freenom  

**✅ Finding:**  
IOC enrichment complete — all critical elements for blocking were identified.

**🛡️ Actionable Insight:**  
These IOCs can now be added to DNS filters, firewalls, and proxy blocklists to **prevent further communication with attacker infrastructure**.

![image](https://github.com/user-attachments/assets/e22e92ee-43e9-4477-8484-ce12bd5a7824)

İf we look at the previous question, we can see the reference link, if we enter this link in google.

![image](https://github.com/user-attachments/assets/0abdc62c-bb19-4816-b774-19d2ac2ef28a)

Fig: Twitter post from given url in terminal, where we can see Registar, C2 and Threatdomain.

---

## 5. What Can the Malware Actually Do?

**📍 Scenario:**  
The same IRATA file was submitted to [JoeSandbox](https://www.joesandbox.com/) for dynamic analysis to assess its behavior and potential impact.

**🔬 Investigation:**  
Within the **Collection** tab of the sandbox report, I identified several actions targeting user privacy and device data.

**✅ Techniques (MITRE-aligned):**

- Access Contact List  
- Access Stored Application Data  
- Capture SMS Messages  
- Location Tracking  
- Network Information Discovery  

**😨 Impact:**  
The malware is capable of exposing **sensitive executive communication, stored data, location**, and **SMS content**, posing a serious **privacy and surveillance risk**.


![image](https://github.com/user-attachments/assets/4b7e9b3f-8d12-4493-879f-8d243241480b)

Fig: Collection tab from given URL https://www.joesandbox.com/analysis/1319345/1/html 

---

## 6. Outbound Connection Missed by a Junior Analyst

**📍 Scenario:**  
A junior analyst dismissed an event involving the private IP `192.236.198.236`, which had triggered outbound network connections.

**📁 Investigation:**  
I opened `full_ip-port.csv` and manually searched for the IP. This revealed that it was communicating over **non-standard ports 1505 and 1506**.

**✅ Finding:**  
Outbound traffic to external IP using ports 1505 and 1506 — both uncommon for standard business operations.

**📌 Lesson:**  
Unusual outbound ports should **never be ignored**, as they can indicate **covert channels** used for command-and-control (C2) or data exfiltration.


![image](https://github.com/user-attachments/assets/d0b11d97-f8d5-45e1-b060-41c8e1b2eb1a)

Fig: searching IP  via Edit search text editor of full_ip-port.csv file

![image](https://github.com/user-attachments/assets/38e60627-7124-4009-a284-dc0fef9f43fe)

Fig: Found IP and ports of the given Ips.

---

## 7. Hunting Down the C2 Domain

**📍 Scenario:**  
After identifying suspicious outbound activity from IP `192.236.198.236`, we needed to uncover the domain associated with it.

**🔗 Investigation:**  
Using the provided reference link in the dataset, I conducted an open-source lookup and discovered the associated **Command and Control (C2) domain**.

**✅ Result:**  
`ianticrish.tk`

**🎯 Next Step:**  
This domain was added to the **threat block list** to prevent further communication between internal assets and the attacker-controlled infrastructure.


![image](https://github.com/user-attachments/assets/f1adf690-a430-40e6-baf6-f331be156a9e)

Fig: Found reference link in Gnumeric.

![image](https://github.com/user-attachments/assets/fb3a6a08-c815-4c85-ae81-3d45b75ae6e4)

Fig: After pasting in the reference link in Google, I found this – ianticrish[.]tk

---

## 8. How Did It Get In?

**📍 Scenario:**  
After identifying the C2 domain and malicious activity, we needed to determine how the malware entered the network.

**🧠 Investigation:**  
Based on observed behavior, sandbox analysis, and mapping to the MITRE ATT&CK framework, the activity aligned with a **phishing-based delivery method**.

**✅ Technique:**  
[T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)

**📌 Lesson:**  
Even a **single click** on a malicious email attachment or link can be the **entry point for a full compromise**. Early detection and user awareness are critical.


![image](https://github.com/user-attachments/assets/7e28d57a-b8bc-4423-9884-f35c1a311a04)

Fig: found T1566 from the  task given to us

---

## 9. Weaponized Document Identification

**📍 Scenario:**  
The Endpoint Detection and Response (EDR) team required the exact filename of the weaponized document to initiate internal scans and containment.

**🧾 Investigation:**  
Using [JoeSandbox](https://www.joesandbox.com/) analysis, I reviewed the file behavior and metadata.

**✅ Malicious DOC Identified:**  
`08.2022 pazartesi sipari#U015fler.docx`

**💡 Use:**  
This filename was added to internal IOC scanning tools to locate and isolate any matching artifacts within the enterprise.


![image](https://github.com/user-attachments/assets/7569852e-f2a0-43a1-ae1d-d2345466db21)

Fig: Used https://www.joesandbox.com/analysis/680865/0/irxml  and 08.2022 pazartesi sipari#U015fler.docx

---

## 10. Dropped Payload from Document

**📍 Scenario:**  
After identifying the weaponized Word document, we needed to determine what secondary payload it dropped during execution.

**📁 Investigation:**  
Using the same [JoeSandbox](https://www.joesandbox.com/) session, I extracted the dropped file from the behavior analysis section.

**✅ Dropped File Identified:**  
`NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR`

**⚠️ Use:**  
This `.JAR` file hash was added to the **EDR blacklist** and **network monitoring rules** to prevent future execution or lateral spread within the environment.


![image](https://github.com/user-attachments/assets/827ed3ae-9c80-4a53-a052-c5be3238d90f)

Fig: Used https://www.joesandbox.com/analysis/680865/0/irxml  
And found NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR


---

## 11. Can Discord Be Malicious?

**📍 Scenario:**  
Executives raised concerns about Discord potentially being used as a malware delivery channel. We needed to investigate whether it had been used to distribute malicious files.

**🔍 Investigation:**  
I searched through `full_urls.csv` and found **multiple entries** referencing Discord’s CDN infrastructure.

**✅ URL Pattern Identified:**  
`https://cdn.discordapp.com/attachments/`

**📌 Implication:**  
Files shared through Discord can **bypass traditional perimeter security controls**, making it a viable platform for **malware distribution and data exfiltration**. Monitoring such CDNs is essential in modern threat detection.


![image](https://github.com/user-attachments/assets/0ff24db8-1b54-4b1b-b200-fd5c9611981f)

Fig: Used text editor solve this problem After searching ‘discord’ on  Text Editor of full_urls.csv file and found https://cdn.discordapp.com/attachments/……..

---

## 12. How Common is Discord in Our Logs?

**📍 Scenario:**  
After identifying Discord as a potential threat vector, the next step was to understand the scale of its presence in our network logs.

**🧮 Investigation:**  
I used the `grep -c` command in the terminal to count all instances of `https://cdn.discordapp.com/attachments/` across the `full_urls.csv` file.

**✅ Finding:**  
**565** references to Discord’s CDN were identified.

**📊 Insight:**  
This level of activity suggests **high usage** of Discord as a file-sharing medium. It warrants **proactive monitoring**, **filtering**, or **policy review** within the organization to mitigate risk.


![image](https://github.com/user-attachments/assets/0f414070-6a9f-43f6-b9a9-0633280f2d25)


---

## 13. Which Malware is Using Discord?

**📍 Scenario:**  
Following the discovery of Discord CDN usage, I needed to identify which malware families were leveraging this platform for distribution.

**🧠 Investigation:**  
A focused text search across the dataset revealed multiple references tying the Discord links to the **Dridex** malware family.

**✅ Malware Name Identified:**  
**Dridex**

**💡 Insight:**  
Dridex is a **legacy banking trojan** known for credential theft and financial fraud. Its use of **modern delivery channels like Discord** highlights how attackers adapt trusted platforms for evasion and persistence.


![image](https://github.com/user-attachments/assets/28ba6a33-1a6d-43f0-a9d2-6b3c9f1452be)
![image](https://github.com/user-attachments/assets/3e9925d1-10c6-4816-8f58-125176a5295d)


---

## 14. High Confidence Blocking

**📍 Scenario:**  
To improve proactive threat prevention, I was tasked with identifying how many IOCs in the dataset were safe to block with high confidence.

**📊 Investigation:**  
I filtered the threat intelligence data to isolate entries with a **confidence score of 100**, indicating they were fully verified and reliable.

**✅ Safe to Block:**  
**39,992** IOCs

**🎯 Outcome:**  
This allowed for the implementation of **high-confidence blocks** in the web proxy and firewall rulesets — significantly reducing **false positives** and strengthening overall **threat prevention posture**.


![image](https://github.com/user-attachments/assets/f810b330-ce14-4c3c-bf14-315ee3be6d1b)

---

## 15. Unknown Malware with Suspicious Port

**📍 Scenario:**  
Suspicious activity was observed originating from **source port 8001**, which raised red flags for potential malware communication.

**🔎 Investigation:**  
I filtered `full_ip-port.csv` to isolate entries using port 8001 and marked with **"Unknown malware"** in the classification column.

**✅ IP Found:**  
`107.172.214.23`

**📌 Action:**  
This IP was **flagged for full packet capture and continuous monitoring** to analyze its behavior further and correlate with other threat activity.


![image](https://github.com/user-attachments/assets/bb27a69d-c1e5-4f7f-bdc4-81783a0f73de)


---

## 16. What’s the Exploit?

**📍 Scenario:**  
After identifying suspicious behavior tied to `107.172.214.23`, the next step was to determine which known vulnerability the attacker was attempting to exploit.

**🌐 Investigation:**  
Using the reference provided in the dataset and performing open-source lookup, I confirmed the IP was attempting to exploit a critical Java-based remote code execution vulnerability.

**✅ CVE Identified:**  
`CVE-2021–44228`

**✅ Nickname:**  
**Log4Shell**

**😨 Impact:**  
**Log4Shell** is considered one of the **most devastating and widely exploited Java vulnerabilities** in recent years. It allowed unauthenticated remote code execution across thousands of applications globally and was actively abused in targeted and opportunistic attacks.


![image](https://github.com/user-attachments/assets/a25de387-7fb5-4e18-9286-695f07f0344f)

note this reference link and paste google

![image](https://github.com/user-attachments/assets/f906be39-e557-4908-8c46-c51d4b854c63)

this page and CVE id is CVE-2021–44228

![image](https://github.com/user-attachments/assets/2cffa8d4-bd29-4820-882c-9fe512aae422)

Fig: nickname for this CVE, source Google

---


## 🎯 Final Thoughts

This threat intelligence investigation challenged both my **technical capabilities** and **analytical mindset**. It required identifying attacker infrastructure, investigating suspicious behavior, enriching IOCs, and mapping activity to frameworks like **MITRE ATT&CK**.

From hunting C2 domains to decoding malware behavior, every scenario deepened my understanding of how threats operate — and more importantly, how defenders must respond.

> 🛡️ **Threat intelligence isn’t just about collecting data — it’s about connecting the dots to protect people.**

---


