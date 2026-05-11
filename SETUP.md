# SETUP – Technische Installationsanleitung

Schritt-für-Schritt-Anleitung zum Nachbauen der gesamten Lab-Umgebung.

---

## Voraussetzungen

- Azure-Account (kostenlos unter https://azure.microsoft.com/free/)
- Webbrowser mit Zugriff auf https://portal.azure.com
- Ca. 2–3 Stunden Zeit

---

## Phase 1 – Azure-Infrastruktur

### 1.1 Resource Group

1. Azure Portal öffnen → Suchleiste → `Resource Groups`
2. **Erstellen** klicken
3. Werte eintragen:
   - Name: `RG-SOCLab`
   - Region: `West Europe`
4. **Überprüfen + Erstellen** → **Erstellen**

> 📸 Screenshot speichern als: `screenshots/01_resource-group.png`

---

### 1.2 Virtual Network

1. Suchleiste → `Virtual Networks` → **Erstellen**
2. Werte:
   - Resource Group: `RG-SOCLab`
   - Name: `VN-SOCLab`
   - Region: `West Europe`
3. Alle anderen Felder auf Standard lassen
4. **Erstellen**

> 📸 Screenshot speichern als: `screenshots/02_virtual-network.png`

---

### 1.3 Exposed Test System erstellen

1. Suchleiste → `Virtual Machines` → **Erstellen**
2. Konfiguration:

| Feld | Wert |
|---|---|
| Resource Group | `RG-SOCLab` |
| VM-Name | `TI-NET-EAST-1` |
| Region | `West Europe` |
| Image | Windows 10 Pro oder Windows Server 2022 |
| Größe | `Standard_B1s` |
| Benutzername | selbst wählen – **merken!** |
| Passwort | sicheres Passwort – **merken!** |

3. **Netzwerk-Tab:** „Delete public IP and NIC when VM is deleted" ✅ aktivieren
4. **Monitoring-Tab:** Boot-Diagnose **deaktivieren**
5. **Erstellen** (dauert ca. 3–5 Minuten)

> 📸 Screenshot speichern als: `screenshots/03_vm-created.png`

---

### 1.4 Network Security Group – alle Ports öffnen

1. Resource Group `RG-SOCLab` öffnen
2. NSG öffnen (Name endet auf `-nsg`)
3. Bestehende RDP-Inbound-Regel **löschen**
4. Neue Inbound-Regel:

| Feld | Wert |
|---|---|
| Quelle | Any |
| Quell-Port | `*` |
| Ziel | Any |
| Ziel-Port | `*` |
| Protokoll | Any |
| Aktion | **Allow** |
| Priorität | `100` |
| Name | `DANGER_AllowAll` |

5. **Speichern**

> 📸 Screenshot speichern als: `screenshots/04_nsg-rule.png`

---

### 1.5 Windows Firewall auf der VM deaktivieren

1. Öffentliche IP der VM aus dem Azure Portal kopieren
2. Per RDP verbinden (Windows: `mstsc` → IP eingeben)
3. In der VM: `Win + R` → `wf.msc` → Enter
4. „Windows Defender Firewall-Eigenschaften" öffnen
5. Für **Domain**, **Private** und **Public**: Firewall-Status auf **Aus** setzen
6. **OK**

> 📸 Screenshot speichern als: `screenshots/05_firewall-disabled.png`

---

## Phase 2 – SIEM: Microsoft Sentinel

### 2.1 Log Analytics Workspace

1. Suchleiste → `Log Analytics Workspaces` → **Erstellen**
2. Werte:
   - Resource Group: `RG-SOCLab`
   - Name: `LAW-SOCLab`
   - Region: `West Europe`
3. **Erstellen**

> 📸 Screenshot speichern als: `screenshots/06_log-analytics-workspace.png`

---

### 2.2 Microsoft Sentinel einrichten

1. Suchleiste → `Microsoft Sentinel` → **Erstellen**
2. Workspace `LAW-SOCLab` auswählen → **Hinzufügen**

> 📸 Screenshot speichern als: `screenshots/07_sentinel-overview.png`

---

### 2.3 Windows Security Events verbinden

1. Sentinel → **Content Management → Content Hub**
2. `Windows Security Events` suchen → **Installieren**
3. Nach Installation: **Verwalten**
4. `Windows Security Events via AMA` auswählen → **Connector-Seite öffnen**
5. **Data Collection Rule** erstellen:
   - Name: `DCR-Windows`
   - Resources-Tab: VM `TI-NET-EAST-1` auswählen
   - **Erstellen**

> ⏳ 10–20 Minuten warten bis erste Logs erscheinen

> 📸 Screenshot speichern als: `screenshots/08_data-collection-rule.png`

---

## Phase 3 – EDR: Microsoft Defender for Endpoint

### 3.1 Defender for Endpoint aktivieren

1. Im Azure Portal → `Microsoft Defender for Cloud` öffnen
2. **Environment Settings** → Subscription auswählen
3. **Defender Plans** → „Servers" auf **On** stellen
4. **Speichern**

> 📸 Screenshot speichern als: `screenshots/09_defender-for-cloud.png`

---

### 3.2 VM in Defender Portal sehen

1. https://security.microsoft.com öffnen
2. **Assets → Devices** → VM `TI-NET-EAST-1` sollte erscheinen
3. Geräteprofil öffnen → Alerts und Timeline prüfen

> ⏳ Kann bis zu 1 Stunde dauern bis das Gerät erscheint

> 📸 Screenshot speichern als: `screenshots/10_defender-endpoint-device.png`

---

## Phase 4 – GeoIP Watchlist

### 4.1 CSV herunterladen

- Datei: [geoip-summarized.csv](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/geoip-summarized.csv)
- Direkt herunterladen und lokal speichern

### 4.2 Watchlist importieren

1. Sentinel → **Watchlist** → **Neu**
2. Konfiguration:

| Feld | Wert |
|---|---|
| Name | `GeoIP` |
| Alias | `GeoIP` |
| Quelldatei | `geoip-summarized.csv` hochladen |
| Suchschlüssel | `Network` |

3. **Erstellen** (dauert einige Minuten – ca. 50.000 Einträge)

> 📸 Screenshot speichern als: `screenshots/11_geoip-watchlist.png`

---

## Phase 5 – Erste Angriffe sehen

### 5.1 KQL-Query ausführen

1. Sentinel → **Logs**
2. Query eingeben:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, Computer
| order by TimeGenerated desc
```

3. **Ausführen**

> ⏳ Falls keine Ergebnisse: Noch 30–60 Minuten warten. Angriffe kommen garantiert!

> 📸 Screenshot speichern als: `screenshots/12_first-brute-force-logs.png`

---

## Phase 6 – Angriffsmap erstellen

### 6.1 Workbook anlegen

1. Sentinel → **Workbooks** → **Neu hinzufügen** → **Code-Editor öffnen**
2. Inhalt aus `playbooks/attackmap-workbook.json` einfügen
3. **Speichern** → Name: `SOC-Angriffsmap`

> 📸 Screenshot speichern als: `screenshots/13_attackmap.png`

---

## Phase 7 – Schwachstellenmanagement

### 7.1 Defender Vulnerability Management

1. https://security.microsoft.com → **Vulnerability Management → Dashboard**
2. Device `TI-NET-EAST-1` auswählen
3. **Discovered Vulnerabilities** ansehen
4. Nach CVE-Severity filtern: **Critical**

> 📸 Screenshot speichern als: `screenshots/14_vulnerability-management.png`

---

## Phase 8 – SOAR Playbook

### 8.1 Logic App Playbook importieren

1. Azure Portal → **Logic Apps** → **Hinzufügen**
2. Aus ARM-Template erstellen → Datei `playbooks/auto-block-ip.json` hochladen
3. Sentinel → **Automation** → Playbook mit Analytics Rule verknüpfen

> 📸 Screenshot speichern als: `screenshots/15_soar-playbook.png`

---

## ⚠️ Aufräumen nach dem Lab

**Wichtig:** Um Kosten zu vermeiden, nach dem Lab alle Ressourcen löschen!

1. Azure Portal → **Resource Groups** → `RG-SOCLab`
2. **Resource Group löschen** → alle enthaltenen Ressourcen werden automatisch entfernt
3. Bestätigen → fertig

---

*Alle Screenshots in den Ordner `screenshots/` ablegen und im README verlinken.*
