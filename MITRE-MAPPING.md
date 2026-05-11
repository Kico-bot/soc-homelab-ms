# MITRE ATT&CK Mapping – Beobachtete Angriffstechniken

Mapping der im Lab beobachteten Angriffe auf das MITRE ATT&CK Framework (Enterprise).  
Alle Techniken wurden durch reale Log-Daten aus Microsoft Sentinel bestätigt.

---

## Übersicht

| Tactic | Technique ID | Technique Name | Erkennungsquelle |
|---|---|---|---|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | NSG Flow Logs |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | NSG Flow Logs |
| Initial Access | T1078 | Valid Accounts | SecurityEvent 4625 |
| Initial Access | T1110.001 | Brute Force: Password Guessing | SecurityEvent 4625 |
| Initial Access | T1110.003 | Brute Force: Password Spraying | SecurityEvent 4625 |
| Initial Access | T1190 | Exploit Public-Facing Application | Defender for Endpoint |
| Defense Evasion | T1078.003 | Valid Accounts: Local Accounts | SecurityEvent 4624/4625 |
| Credential Access | T1110 | Brute Force | SecurityEvent 4625 |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | SecurityEvent 4624 |

---

## Detailansicht je Technik

### T1110.001 – Brute Force: Password Guessing

**Beschreibung:** Angreifer versuchen systematisch Passwörter für bekannte Benutzernamen.

**Beobachtung im Lab:**
- EventID `4625` (fehlgeschlagene Anmeldung) in hoher Frequenz
- Ziel-Accounts: `administrator`, `admin`, `user`, `test`, `guest`, `Administrator`
- Herkunfts-IPs aus CN, RU, BR, NL

**KQL-Erkennungsregel:**
```kql
SecurityEvent
| where EventID == 4625
| summarize Versuche = count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where Versuche > 10
| extend Tactic = "Credential Access"
| extend Technique = "T1110.001 – Brute Force: Password Guessing"
```

> 📸 Screenshot: `screenshots/12_first-brute-force-logs.png`

---

### T1110.003 – Brute Force: Password Spraying

**Beschreibung:** Ein Passwort wird gegen viele verschiedene Accounts getestet (umgeht Account-Lockout-Policies).

**Beobachtung im Lab:**
- Gleiche Quell-IP, viele verschiedene Ziel-Accounts innerhalb kurzer Zeit
- Typisches Muster: 1 Versuch pro Account, dann nächster Account

**KQL-Erkennungsregel:**
```kql
SecurityEvent
| where EventID == 4625
| summarize AnzahlAccounts = dcount(Account) by IpAddress, bin(TimeGenerated, 10m)
| where AnzahlAccounts > 5
| extend Tactic = "Credential Access"
| extend Technique = "T1110.003 – Password Spraying"
```

---

### T1595 – Active Scanning

**Beschreibung:** Angreifer scannen öffentlich erreichbare IP-Adressen nach offenen Ports und Diensten.

**Beobachtung im Lab:**
- NSG Flow Logs zeigen massenhafte Verbindungsversuche auf verschiedene Ports
- Portscan-Muster erkennbar: sequenzielle Ports von einer IP

**KQL-Erkennungsregel:**
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "ExternalPublic"
| summarize Ports = dcount(DestPort_d), Verbindungen = count()
    by SrcIP_s, bin(TimeGenerated, 5m)
| where Ports > 20
| extend Tactic = "Reconnaissance"
| extend Technique = "T1595 – Active Scanning"
```

---

### T1021.001 – Remote Services: RDP

**Beschreibung:** Angreifer nutzen RDP (Remote Desktop Protocol) für den Zugriff auf Systeme.

**Beobachtung im Lab:**
- Alle Brute-Force-Versuche zielten auf RDP (Port 3389)
- Erfolgreiche Anmeldungen wären als EventID `4624` + Logon Type 10 sichtbar

**KQL-Erkennungsregel:**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Account, IpAddress, Computer
| extend Tactic = "Lateral Movement"
| extend Technique = "T1021.001 – Remote Desktop Protocol"
```

---

## ATT&CK Navigator Visualisierung

Die folgende Tabelle zeigt die Abdeckung nach Tactic-Kategorie:

| Tactic | Techniken abgedeckt | Erkennungsrate |
|---|---|---|
| Reconnaissance | 2 | ✅ Vollständig |
| Initial Access | 3 | ✅ Vollständig |
| Credential Access | 2 | ✅ Vollständig |
| Defense Evasion | 1 | ⚠️ Teilweise |
| Lateral Movement | 1 | ✅ Vollständig |
| Execution | 0 | ❌ Nicht abgedeckt (kein C2 im Lab) |
| Persistence | 0 | ❌ Nicht abgedeckt |

> **Hinweis:** Das Lab fokussiert sich auf die Erkennungsebene. Execution und Persistence-Techniken würden eine aktive Kompromittierung voraussetzen, die im Lab nicht simuliert wurde.

---

## Weiterführend

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Microsoft Sentinel MITRE ATT&CK Coverage](https://docs.microsoft.com/azure/sentinel/mitre-coverage)
- [Defender XDR – ATT&CK Mapping](https://security.microsoft.com/threatanalytics3)
