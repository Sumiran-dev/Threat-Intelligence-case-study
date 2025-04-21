🧠 Threat Intelligence Case Study – SOC Investigation Walkthrough
This investigation was part of a simulated SOC environment, where I stepped into the role of a cybersecurity analyst responding to alerts from multiple sources. Each task reflected a real-world scenario, requiring the use of open-source intelligence (OSINT), threat feeds, sandbox analysis, and CSV parsing to uncover hidden IOCs, malware delivery methods, and attacker infrastructure.
This wasn’t just about finding answers — it was about thinking like an analyst under pressure, asking why something happened, not just what.

1️. Strange Beacon to a Suspicious GIF
📍Scenario: Our SOC received alerts of multiple internal systems reaching out to http://45.63.126.199/dot.gif.
🔎 I searched this IOC in Gnumeic and uncovered its association with Cobalt Strike, a known post-exploitation tool used by advanced threat actors.
✅ Finding: Cobalt Strike beacon activity
🧠 Thought Process: This was likely a payload staging or command channel.

![image](https://github.com/user-attachments/assets/57d1fabd-fe4f-40c0-b303-cef7294405bd)

Fig: CSV file location

![image](https://github.com/user-attachments/assets/a906f993-8c5a-486c-b69f-d41b1398c313)

![image](https://github.com/user-attachments/assets/e8f734e7-230f-4904-9b9d-ae4842ca3597)

![image](https://github.com/user-attachments/assets/898519fb-865c-41c3-86bf-7c184dc022a9)

Fig: After  searching url: hxxp://45[.]63[.]126[.]199/dot[.]gif, in Gnumeric, I found Cobalt Strike which is related to network connections from 3 internal hosts towards hxxp://45[.]63[.]126[.]199/dot[.]gif

2️. Counting Repeated Beacon Attempts
📍Scenario: How many times has this endpoint dot.gif appeared in our threat feeds?
🔧 Using CLI, I analyzed full_urls.csv and other exports to find 568 instances.
✅ Finding: 568 URLs hitting the same endpoint
📌 Insight: A widespread campaign — multiple attempts across different sources.


![image](https://github.com/user-attachments/assets/0458a569-d0bf-4b08-bf73-e3ef442f8153)
 
Fig: Using grep command to find the total number of dot.gif, used by all export files, using Ubuntu CLI

3️. Suspicious File on an Executive’s Android Device
📍Scenario: An Android file was quarantined, and we needed to assess its risk.
🔍 I queried the SHA256 hash (6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5) and found it linked to IRATA spyware via MalwareBazaar.
✅ Finding: IRATA – a mobile surveillance tool
💡 Takeaway: Quick hash lookups can uncover threats hiding in plain sight.

![image](https://github.com/user-attachments/assets/abd3cd0f-59fb-4e2b-8ca7-96d1d5d565c4)
 
Fig: Spotting IRATA spyware

4️. Digging Deeper into IRATA
📍Scenario: We needed IOC details for containment and blocking.
🌐 Using the reference link, I discovered:
•	Threat Name: IRATA
•	C2 Domain: uklivemy.gq
•	IP: 20.238.64.240
•	Registrar: Freenom
✅ IOC Enrichment Complete
🛡️ Actionable Insight: These details can be blocked at the DNS and proxy level.

 ![image](https://github.com/user-attachments/assets/4e65009f-206c-4cf2-8c56-81f57d586034)

İf we look at the previous question, we can see the reference link, if we enter this link in google.

 ![image](https://github.com/user-attachments/assets/2525c3f4-659c-4adf-869d-cc7ae36bb4fe)
Fig: Twitter post from given url in terminal, where we can see Registar, C2 and Threatdomain.


5️. What Can the Malware Actually Do?
📍Scenario: The same file was analyzed in JoeSandbox. What damage could it cause?
🔬 Inside the Collection tab, I noted 5 techniques targeting mobile privacy.
✅ Techniques (MITRE-aligned):
•	Access Contact List
•	Access Stored Application Data
•	Capture SMS Messages
•	Location Tracking
•	Network Information Discovery
😨 Impact: This could expose sensitive executive communication and movement.

 ![image](https://github.com/user-attachments/assets/de00fd79-a4b8-4263-be7f-d95f4289fe1b)
Fig: Collection tab from given URL https://www.joesandbox.com/analysis/1319345/1/html 

6️⃣ Outbound Connection Missed by a Junior Analyst
📍Scenario: A private IP 192.236.198.236 triggered connections but was dismissed.
📁 I opened full_ip-port.csv and identified ports 1505 and 1506.
✅ Finding: Two non-standard outbound ports
📌 Lesson: Unusual outbound traffic should never be ignored.

![image](https://github.com/user-attachments/assets/f92748e6-139d-47ab-9406-7d2dc3c7c7aa) 
Fig: searching IP  via Edit search text editor of full_ip-port.csv file

 ![image](https://github.com/user-attachments/assets/d8c63a75-58d3-4cc8-a998-34d385e8f444)
Fig: Found IP and ports of the given Ips.


7️. Hunting Down the C2 Domain
📍Scenario: We needed the domain behind 192.236.198.236.
🔗 Using the provided reference, I found the C2 domain:
✅ Result: ianticrish.tk
🎯 Next Step: Add domain to our threat block list.

 ![image](https://github.com/user-attachments/assets/2e6380b3-6e64-4f37-bc31-7577fa5274e2)
Fig: Found reference link in Gnumeric.

 ![image](https://github.com/user-attachments/assets/5f1c4071-7d30-471a-a1cb-b6c5de503762)
Fig: After pasting in the reference link in Google, I found this – ianticrish[.]tk


8️. How Did It Get In?
📍Scenario: Determine the likely delivery method.
🧠 Based on the behavior and MITRE mapping, this was a phishing attack.
✅ Technique: T1566 – Phishing
📌 Lesson: Even one click can start a breach.


 ![image](https://github.com/user-attachments/assets/329e430a-4fba-40f1-b0d6-c62c849f6c7e)
Fig: found T1566 from the  task given to us

9️. Weaponized Document Identification
📍Scenario: EDR needed the filename to scan internally.
🧾 JoeSandbox analysis revealed:
✅ Malicious DOC: 08.2022 pazartesi sipari#U015fler.docx
💡 Use: IOC scanning in enterprise systems.

 ![image](https://github.com/user-attachments/assets/f6228aa2-35fe-4520-8353-ded49060c802)
Fig: Used https://www.joesandbox.com/analysis/680865/0/irxml  and 08.2022 pazartesi sipari#U015fler.docx


🔟 Dropped Payload from Document
📍Scenario: What file did the Word doc drop?
📁 I extracted this from the same sandbox session.
✅ Dropped File: NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR
⚠️ Use: Add to EDR hash blacklists.

 ![image](https://github.com/user-attachments/assets/fa7865ce-f843-4b1e-bd0b-0a6bd41c91e4)
Fig: Used https://www.joesandbox.com/analysis/680865/0/irxml  
And found NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR

11. Can Discord Be Malicious?
📍Scenario: Execs asked if Discord is a threat vector.
🔍 I searched full_urls.csv and found multiple Discord CDN links.
✅ URL Pattern: https://cdn.discordapp.com/attachments/
📌 Implication: Files shared on Discord can bypass security scanning.

 ![image](https://github.com/user-attachments/assets/ce3c3b9e-5cf9-4a74-ba65-14331b661fd9)
Fig: Used text editor solve this problem After searching ‘discord’ on  Text Editor of full_urls.csv file and found https://cdn.discordapp.com/attachments/……..

12. How Common is Discord in Our Logs?
📍Scenario: Need to understand scale.
🧮 Used CLI with grep -c to count:
✅ Finding: 565 references to Discord CDN
📊 Insight: High usage warrants content filtering or monitoring.

 ![image](https://github.com/user-attachments/assets/49af4b81-822d-43a1-8430-49e7b8bdf434)



13. Which Malware is Using Discord?
📍Scenario: Identify malware family tied to Discord usage.
🧠 Text search revealed multiple references to:
✅ Malware Name: Dridex
💡 Insight: Legacy banking trojan, now using modern delivery channels.
 
 ![image](https://github.com/user-attachments/assets/4086bb30-f61b-4900-9ddd-28d65f587d0c)

![image](https://github.com/user-attachments/assets/838a352a-9c42-4f04-832f-a0d5494ce13a)



14. High Confidence Blocking
📍Scenario: How many threat entries can we safely block?
📊 I filtered entries with confidence = 100.
✅ Safe to Block: 39,992 rows
🎯 Outcome: Reduced false positives, improved threat prevention.

 ![image](https://github.com/user-attachments/assets/daf6234b-4c0e-4a41-ae93-6033f72d023f)


15. Unknown Malware with Suspicious Port
📍Scenario: Activity observed from source port 8001.
🔎 Filtered full_ip-port.csv on port 8001 and Unknown malware.
✅ IP Found: 107.172.214.23
📌 Action: Mark for full packet capture.
 
![image](https://github.com/user-attachments/assets/81087343-7beb-4dbb-9f10-965c90236597)


16. What’s the Exploit?
📍Scenario: What CVE was this IP trying to exploit?
🌐 Reference lookup revealed:
✅ CVE: CVE-2021–44228
✅ Nickname: Log4Shell
😨 Impact: One of the most devastating Java-based RCE vulnerabilities.

 ![image](https://github.com/user-attachments/assets/cd608ed7-5451-48a0-93cd-eaeeac0b2500)
note this reference link and paste google

 ![image](https://github.com/user-attachments/assets/40afe02f-aa03-4bee-b39a-6829bd350087)
this page and CVE id is CVE-2021–44228

 ![image](https://github.com/user-attachments/assets/4f10dd93-1b83-44cd-9263-a483189025fb)
Fig: nickname for this CVE, source Google


🎯 Final Thoughts
This threat intel investigation tested both technical skills and analytical thinking — how to spot patterns, investigate quickly, and draw out useful insights. From hunting C2 domains to decoding malware behavior and enriching IOCs, every step reinforced a core idea:
Threat intelligence isn’t just about data — it’s about connecting the dots to protect people.


