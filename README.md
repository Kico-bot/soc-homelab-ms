# Cloud-Based SOC Homelab – Microsoft Security Stack

> 

---

## Projektziel & Relevanz für den Unternehmenseinsatz

Dieses Projekt simuliert eine produktionsnahe SOC-Umgebung (Security Operations Center) in der Cloud. Ziel war es, den vollständigen **Detection-and-Response-Zyklus** — von der Log-Erfassung über die Bedrohungserkennung bis hin zur Incident-Analyse — hands-on zu erarbeiten und zu dokumentieren.

Die gewonnenen Kenntnisse sind direkt auf reale Unternehmensumgebungen übertragbar:

- **SIEM-Betrieb** mit Microsoft Sentinel (Regelwerke, KQL, Workbooks)
- **EDR/XDR-Integration** über Microsoft Defender for Endpoint & Defender XDR
- **NDR-Konzepte** durch Netzwerkanalyse auf Azure-Ebene (NSG Flow Logs, Threat Intelligence)

---

## Architektur

```
┌─────────────────────────────────────────────────────────────┐
│                        AZURE CLOUD                          │
│                                                             │
│  ┌──────────────────┐        ┌──────────────────────────┐  │
│  │  Windows 10 VM   │        │  Microsoft Sentinel       │  │
│  │  (Exposed Test)  │──────▶ │  (SIEM / SOAR)           │  │
│  │                  │  Logs  │                           │  │
│  │  • RDP exponiert │        │  • Analytics Rules        │  │
│  │  • Sysmon aktiv  │        │  • KQL Queries            │  │
│  │  • AMA Agent     │        │  • Workbooks / Maps       │  │
│  └──────────────────┘        │  • SOAR Playbooks         │  │
│                              └──────────────────────────┘  │
│  ┌──────────────────┐        ┌──────────────────────────┐  │
│  │  Microsoft       │        │  Defender Vulnerability  │  │
│  │  Defender XDR    │◀──────▶│  Management              │  │
│  │  (EDR/XDR)       │        │  (CVE-Tracking, Patching)│  │
│  └──────────────────┘        └──────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Log Analytics Workspace  ←  zentrale Datenplattform │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
          ▲
          │ Echte Angriffe aus dem Internet
          │ (Brute-Force, Credential Stuffing, Port Scans)
```

---

## Eingesetzte Technologien & Produkte

| Kategorie | Produkt | Funktion |
|---|---|---|
| **SIEM** | Microsoft Sentinel | Log-Korrelation, Alerting, Dashboards |
| **EDR** | Microsoft Defender for Endpoint | Endpoint Detection & Response |
| **XDR** | Microsoft Defender XDR | Übergreifende Angriffserkennung (E-Mail, Identity, Endpoint) |
| **NDR** | Azure NSG Flow Logs + Sentinel | Netzwerkverkehr-Analyse, anomale Verbindungen |
| **VM** | Microsoft Defender Vulnerability Management | CVE-Erkennung, Risikobewertung, Patch-Priorisierung |
| **SOAR** | Sentinel Playbooks (Azure Logic Apps) | Automatisierte Incident-Response |
| **Log-Transport** | Azure Monitor Agent (AMA) | Strukturierte Log-Weiterleitung via DCR |
| **Sprache** | KQL (Kusto Query Language) | Threat Hunting, Regelentwicklung |
| **Geoanreicherung** | GeoIP Watchlist | IP-zu-Standort-Mapping für Angreifer |

---

## Aufbau & Konfiguration

### 1. Azure-Infrastruktur

- **Resource Group** `RG-SOCLab` als logischer Container für alle Ressourcen
- **Virtual Network** mit definiertem Adressraum und Subnetz-Segmentierung
- **Windows 10 VM** als Exposed Test System (bewusst exponiert, könnte als Honeypot dienen)
- **Network Security Group** zur Simulation einer offenen Angriffsfläche

### 2. Log-Erfassung & SIEM-Anbindung

- **Log Analytics Workspace** als zentrales Daten-Repository
- **Azure Monitor Agent (AMA)** auf der VM installiert
- **Data Collection Rule (DCR)** für strukturierte Weiterleitung von Windows Security Events
- **Microsoft Sentinel** als SIEM auf den Workspace aufgesetzt

### 3. EDR – Microsoft Defender for Endpoint

- Defender for Endpoint auf dem Exposed Test System aktiviert
- **Echtzeit-Schutz**, Verhaltensanalyse und automatische Untersuchung konfiguriert
- Gerät in das **Microsoft 365 Defender-Portal** ongeboardet
- Alerts werden automatisch in Sentinel als Incidents weitergeleitet

### 4. XDR – Microsoft Defender XDR

- **Defender XDR** als übergreifende Korrelationsebene eingerichtet
- Verbindet Signale aus Endpoint, Identity und Cloud in einer einheitlichen Incident-Ansicht
- **Automatic Attack Disruption** zur automatisierten Eindämmung aktiver Angriffe aktiviert
- Sentinel-Connector für bidirektionale Incident-Synchronisation konfiguriert

### 5. NDR – Netzwerkanalyse

- **NSG Flow Logs** aktiviert und in den Log Analytics Workspace geleitet
- Analyse eingehender Verbindungen nach Quell-IP, Port und Protokoll
- Erkennung von **Port-Scans**, **Brute-Force-Wellen** und **geografischen Anomalien**
- Custom Analytics Rule in Sentinel für erhöhtes Verbindungsvolumen aus einzelnen IP-Ranges

### 6. Schwachstellenmanagement – Microsoft Defender Vulnerability Management

- **Defender Vulnerability Management** auf der VM aktiviert
- Automatisches Scanning auf bekannte CVEs (Common Vulnerabilities and Exposures)
- **Exposure Score** und **Device Risk Score** ausgewertet
- Patch-Empfehlungen priorisiert nach CVSS-Score und Ausnutzbarkeit
- Ergebnisse in das Sentinel-Dashboard integriert

### 7. SOAR – Automatisierte Incident Response

Automatisiertes Playbook für hochpriore Alerts:

```
Alert ausgelöst (z.B. 50+ fehlgeschlagene Logins in 5 Min.)
        │
        ▼
Sentinel Analytics Rule greift
        │
        ▼
Logic App Playbook startet automatisch:
  ├── IP in Watchlist „BlockList" eintragen
  ├── NSG-Regel automatisch erstellen (IP blockieren)
  ├── Teams/E-Mail-Benachrichtigung an SOC
  └── Incident in Sentinel als „In Bearbeitung" markieren
```

---

## KQL – Threat Hunting Queries

### Brute-Force-Erkennung (SIEM-Kernanwendung)

```kql
SecurityEvent
| where EventID == 4625
| summarize Versuche = count(),
            ErsterVersuch = min(TimeGenerated),
            LetzterVersuch = max(TimeGenerated)
            by IpAddress, Account, Computer
| where Versuche > 10
| order by Versuche desc
```

### GeoIP-Anreicherung & Angriffskarte

```kql
SecurityEvent
| where EventID == 4625
| extend AttackerIP = IpAddress
| lookup kind=leftouter _GetWatchlist('GeoIP')
    on $left.AttackerIP == $right.Network
| summarize Angriffe = count() by AttackerIP, Country, City, Latitude, Longitude
| order by Angriffe desc
```

### Top-Angreifer-Länder

```kql
SecurityEvent
| where EventID == 4625
| lookup kind=leftouter _GetWatchlist('GeoIP')
    on $left.IpAddress == $right.Network
| summarize Angriffe = count() by Country
| order by Angriffe desc
| take 10
| render barchart
```

### Credential Stuffing – Angriffsziele erkennen

```kql
SecurityEvent
| where EventID == 4625
| summarize Versuche = count() by Account
| order by Versuche desc
| take 20
```

### Anomaler Netzwerkverkehr (NDR via NSG Flow Logs)

```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "ExternalPublic"
| summarize Verbindungen = count() by SrcIP_s, DestPort_d, bin(TimeGenerated, 5m)
| where Verbindungen > 100
| order by Verbindungen desc
```

### Defender Vulnerability Management – kritische CVEs

```kql
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel == "Critical"
| summarize Anzahl = count() by DeviceName, CveId, SoftwareName
| order by Anzahl desc
```

### XDR – Korrelierte Incidents über mehrere Signalquellen

```kql
SecurityIncident
| where Severity in ("High", "Medium")
| extend Tactics = tostring(AdditionalData.tactics)
| summarize Incidents = count() by Title, Severity, Tactics
| order by Incidents desc
```

---

## Ergebnisse & Erkenntnisse

### Beobachtete Angriffsmuster

| Muster | Beobachtung |
|---|---|
| **Reaktionszeit bis erster Angriff** | < 5 Minuten nach VM-Exponierung |
| **Häufigste EventID** | 4625 (fehlgeschlagene Anmeldung) |
| **Top-Ziel-Accounts** | `administrator`, `admin`, `user`, `test`, `guest` |
| **Angriffsherkunft** | CN, RU, NL, US (Exit-Nodes/VPNs), BR |
| **Angriffsmuster** | Systematisches Credential Stuffing, Dictionary Attacks |
| **Defender-Alerts** | Mehrere „Suspicious Remote Activity"-Alerts automatisch generiert |

### Schwachstellenanalyse (Defender Vulnerability Management)

- **3 kritische CVEs** auf ungepatchtem Windows-System erkannt
- Exposure Score initial: **68/100** (hoch)
- Nach simuliertem Patching: Score auf **22/100** reduziert
- CVSS-basierte Priorisierung ermöglichte gezielte Remediation

---

## Lessons Learned & Unternehmensrelevanz

- Ohne Monitoring ist eine exponierte Ressource **innerhalb von Minuten** unter Beschuss. Sichtbarkeit ist alles
- **KQL** ist die Kernkompetenz für Sentinel-Betrieb: eigene Detection Rules sind wertvoller als vorkonfigurierte Alerts
- **XDR-Korrelation** reduziert Alert-Fatigue erheblich. Einzelne Signale ergeben erst im Verbund ein vollständiges Angriffsbild
- **Schwachstellenmanagement** muss priorisiert werden: nicht jedes CVE ist gleich kritisch: CVSS + Ausnutzbarkeit entscheiden
- **SOAR-Automatisierung** spart im Ernstfall wertvolle Zeit und reduziert menschliche Fehler in der Incident-Response

---

## Repository-Struktur

```
📁 soc-homelab-microsoft/
├── 📄 README.md                  ← Projektübersicht & Dokumentation
├── 📄 SETUP.md                   ← Schritt-für-Schritt Installationsanleitung
├── 📄 MITRE-MAPPING.md           ← Mapping der Angriffe auf ATT&CK Framework
├── 📁 screenshots/
│   ├── 01_resource-group.png
│   ├── 02_virtual-network.png
│   ├── 03_vm-created.png
│   ├── 04_nsg-rule.png
│   ├── 05_firewall-disabled.png
│   ├── 06_log-analytics-workspace.png
│   ├── 07_sentinel-overview.png
│   ├── 08_data-collection-rule.png
│   ├── 09_defender-for-cloud.png
│   ├── 10_defender-endpoint-device.png
│   ├── 11_geoip-watchlist.png
│   ├── 12_first-brute-force-logs.png
│   ├── 13_attackmap.png
│   ├── 14_vulnerability-management.png
│   └── 15_soar-playbook.png
├── 📁 kql-queries/
│   ├── KQL SOC Collection.kql
└── 
```

---

## Weiterführende Ressourcen

- [Microsoft Sentinel Dokumentation](https://docs.microsoft.com/azure/sentinel/)
- [Microsoft Defender XDR](https://docs.microsoft.com/microsoft-365/security/defender/)
- [Defender Vulnerability Management](https://docs.microsoft.com/microsoft-365/security/defender-vulnerability-management/)
- [KQL Quick Reference](https://docs.microsoft.com/azure/data-explorer/kql-quick-reference)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---
