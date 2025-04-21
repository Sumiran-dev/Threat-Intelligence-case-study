# 🧠 Threat Intelligence Case Study – SOC Investigation Walkthrough

This investigation was conducted in a simulated SOC environment, where I stepped into the role of a cybersecurity analyst responding to alerts from various sources. Each task mirrored real-world incidents and required techniques like OSINT, malware sandboxing, IOC enrichment, and log analysis to uncover attacker infrastructure and malware activity.

This wasn’t just about answering questions — it was about thinking like an analyst under pressure and asking *why*, not just *what*.

---

## 🔍 1. Strange Beacon to a Suspicious GIF

**Scenario**: Internal systems connected to `http://45.63.126.199/dot.gif`.

- Tool: Gnumeric
- Finding: Cobalt Strike beacon activity
- Insight: Likely command & control or payload staging

![Fig: CSV file location](screenshots/1_csv_location.png)
![Fig: Cobalt Strike match](screenshots/2_cobalt_strike.png)

---

## 📊 2. Counting Repeated Beacon Attempts

**Scenario**: Identify how many times `dot.gif` was seen in threat feeds.

- Tool: CLI + grep
- Result: 568 instances
- Insight: Widespread campaign

![Fig: CLI grep on dot.gif](screenshots/3_dot_grep.png)

---

## 📱 3. Suspicious File on Executive’s Android

**Scenario**: A file was quarantined. What is it?

- Tool: MalwareBazaar
- Hash: `6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5`
- Finding: IRATA spyware

![Fig: IRATA result](screenshots/4_irata.png)

---

## 🌐 4. IOC Enrichment – IRATA Details

- Threat: IRATA  
- C2 Domain: `uklivemy.gq`  
- IP: `20.238.64.240`  
- Registrar: Freenom

![Fig: Reference link lookup](screenshots/5_reference_link.png)

---

## 🧬 5. What Can the Malware Do?

**Sandbox Analysis** via JoeSandbox:

- Techniques:
  - Access Contact List
  - Access Stored App Data
  - Capture SMS Messages
  - Location Tracking
  - Network Information Discovery

![Fig: Collection techniques](screenshots/6_collection_tab.png)

---

## 🚨 6. Ignored Outbound Connection

**Scenario**: Analyst dismissed IP `192.236.198.236`.

- Ports Detected: 1505, 1506
- Tool: CSV log + Text Editor

![Fig: Edit search in CSV](screenshots/7_outbound_ports.png)

---

## 🔗 7. Hunting the C2 Domain

**Reference Analysis** revealed:

- C2: `ianticrish.tk`

![Fig: C2 Domain via reference](screenshots/8_c2_lookup.png)

---

## 📥 8. Phishing as Delivery Method

**Technique**: MITRE T1566 – Phishing  
**Insight**: Likely entry via a malicious email attachment.

![Fig: MITRE T1566](screenshots/9_phishing_technique.png)

---

## 📄 9. Weaponized Document Discovery

**Document Name**:
- `08.2022 pazartesi sipari#U015fler.docx`

![Fig: Weaponized doc](screenshots/10_malicious_doc.png)

---

## 💣 10. Dropped JAR File

**Dropped File**:
- `NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR`

![Fig: Dropped payload](screenshots/11_jar_file.png)

---

## 🧪 11. Discord Abuse Detection

**Scenario**: Can Discord be used to distribute malware?

- Found: `https://cdn.discordapp.com/attachments/`

![Fig: Discord CDN found](screenshots/12_discord_cdn.png)

---

## 📈 12. How Common is Discord in Logs?

- Tool: CLI + `grep -c`
- Result: 565 references

![Fig: Discord URL count](screenshots/13_discord_count.png)

---

## 🧠 13. Malware Over Discord

**Finding**: **Dridex** malware is being distributed via Discord.

![Fig: Dridex on Discord](screenshots/14_dridex_discord.png)

---

## ✅ 14. High Confidence Blocking

**Objective**: Count IOCs with confidence rating = 100

- Safe to Block: 39,992 rows

![Fig: Confidence filtering](screenshots/15_confidence_100.png)

---

## 🕵️ 15. Unknown Malware over Port 8001

**Finding**: IP `107.172.214.23` using port 8001

![Fig: Port 8001 analysis](screenshots/16_port8001_unknown.png)

---

## 🛠️ 16. CVE Exploitation – Log4Shell

- CVE: `CVE-2021–44228`
- Nickname: **Log4Shell**
- Tool: Reference + Google OSINT

![Fig: Log4Shell reference](screenshots/17_log4shell.png)

---

## 🎯 Final Thoughts

This threat intel project sharpened my skills in real-world threat detection, malware attribution, and IOC enrichment. It taught me how to:
- Think like an attacker
- Investigate like a defender
- Connect the dots under pressure

> 🛡️ *Threat intelligence isn’t just about data — it’s about protecting people through insight and action.*

---

## 🧰 Tools & Techniques Used

- ThreatFox, MalwareBazaar, JoeSandbox
- MITRE ATT&CK Navigator
- Gnumeric, CLI (`grep`, `cut`, `wc`)
- CSV parsing, IOC enrichment
- Open-source intelligence (OSINT)
