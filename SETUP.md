# SETUP – Technische Installationsanleitung

Schritt-für-Schritt-Anleitung zum Nachbauen der gesamten Umgebung.

---

## Voraussetzungen

- Azure-Account (kostenlos unter https://azure.microsoft.com/free/)
- Webbrowser mit Zugriff auf https://portal.azure.com

---

## Phase 1 – Azure-Infrastruktur

### 1.1 Resource Group

1. Azure Portal öffnen → Suchleiste → `Resource Groups`
2. **Erstellen** klicken
3. Werte eintragen:
   - Name: `SOCLab`
   - Region: `West Europe`
4. **Überprüfen + Erstellen** → **Erstellen**

> 📸 Screenshot gespeichert als: `screenshots/01_resource-group.png`

---

### 1.2 Virtual Network

1. Suchleiste → `Virtual Networks` → **Erstellen**
2. Werte:
   - Resource Group: `SOCLab`
   - Name: `VN-SOCLab`
   - Region: `West Europe`
3. Alle anderen Felder auf Standard lassen
4. **Erstellen**

> 📸 Screenshot gespeichert als: `screenshots/02_virtual-network.png`

---

### 1.3 Exposed Test System erstellen

1. Suchleiste → `Virtual Machines` → **Erstellen**
2. Konfiguration:

| Feld | Wert |
|---|---|
| Resource Group | `SOCLab` |
| VM-Name | `Ti-GER-1` |
| Region | `West Europe` |
| Image | Windows Server 2022 |
| Größe | `Standard_D2ls_v5` |
| Benutzername | selbst wählen – **merken!** |
| Passwort | sicheres Passwort – **merken!** |

3. **Netzwerk-Tab:** „Delete public IP and NIC when VM is deleted" ✅ aktivieren
4. **Monitoring-Tab:** Boot-Diagnose **deaktivieren**
5. **Erstellen** (dauert ca. 3–5 Minuten)

> 📸 Screenshot gespeichert als: `screenshots/03_vm-created.png`

---

### 1.4 Network Security Group – alle Ports öffnen

1. Resource Group `SOCLab` öffnen
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

> 📸 Screenshot gespeichert als: `screenshots/04_nsg-rule.png`

---

### 1.5 Windows Firewall auf der VM deaktivieren (via PowerShell)

1. Öffentliche IP der VM aus dem Azure Portal kopieren
2. Per RDP verbinden (Windows: `mstsc` → IP eingeben)
3. (Falls das blaue `sconfig`-Menü erscheint, drücke **15** und `Enter`, um zur Kommandozeile zu gelangen).
4. Tippe `powershell` ein und drücke `Enter`, um die PowerShell-Umgebung zu starten.
5. Führe den folgenden Befehl aus, um die Firewall für alle drei Netzwerkprofile (Domain, Private, Public) auf einmal zu deaktivieren:
   ```powershell
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
6. Überprüfe den Status zur Bestätigung mit diesem Befehl:
   ```powershell
   Get-NetFirewallProfile | Select-Object Name, Enabled

> 📸 Screenshot gespeichert als: `screenshots/05_firewall-disabled.png`

---

## Phase 2 – SIEM: Microsoft Sentinel

### 2.1 Log Analytics Workspace

1. Suchleiste → `Log Analytics Workspaces` → **Erstellen**
2. Werte:
   - Resource Group: `SOCLab`
   - Name: `Logspace-SOCLab`
   - Region: `West Europe`
3. **Erstellen**

> 📸 Screenshot gespeichert als: `screenshots/06_log-analytics-workspace.png`

---

### 2.2 Microsoft Sentinel einrichten

1. Suchleiste → `Microsoft Sentinel` → **Erstellen**
2. Workspace `Logspace-SOCLab` auswählen → **Hinzufügen**

> 📸 Screenshot gespeichert als: `screenshots/07_sentinel-overview.png`

---

### 2.3 Windows Security Events verbinden

1. Sentinel → **Content Management → Content Hub**
2. Connect Windows Defender XDR to Workspace
3. `Windows Security Events` suchen → **Installieren**
4. Nach Installation: **Verwalten**
5. `Windows Security Events via AMA` auswählen → **Connector-Seite öffnen**
6. **Data Collection Rule** erstellen:
   - Name: `DCR-Windows`
   - Resources-Tab: VM `SOCLab` auswählen
   - **Erstellen**

> ⏳ 10–20 Minuten warten bis erste Logs erscheinen

> 📸 Screenshot gespeichert als: `screenshots/08_data-collection-rule.png`



---

## Phase 3 – GeoIP Watchlist

### 3.1 CSV herunterladen

- Datei: [geoip-summarized.csv](https://github.com/Kico-bot/soc-homelab-ms/blob/main/geoip-summarized.csv)
- Direkt herunterladen und lokal gespeichert

### 3.2 Watchlist importieren

1. Sentinel → **Watchlist**
2. Microsoft Defender → Microsoft Sentinel → Watchlist → **Neu**
3. Konfiguration:

| Feld | Wert |
|---|---|
| Name | `geoip` |
| Alias | `geoip` |
| Quelldatei | `geoip-summarized.csv` hochladen |
| Suchschlüssel | `Network` |

3. **Erstellen** (dauert einige Minuten – ca. 50.000 Einträge)

> 📸 Screenshot gespeichert als: `screenshots/10_geoip-watchlist.png`
>  📸 Screenshot gespeichert als: `screenshots/10_2.png`

---

## Phase 4 – Erste Angriffe sehen

### 4.1 KQL-Query ausführen

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

> 📸 Screenshot gespeichert als: `screenshots/11_first-brute-force-logs.png`

---

## Phase 5 – Angriffsmap erstellen

### 5.1 Workbook anlegen

1. Microsoft Defender: Sentinel → Thread Management → **Workbooks** → **Neu hinzufügen** → **Edit**
2. Inhalt aus `map.json` einfügen (https://github.com/Kico-bot/soc-homelab-ms/blob/main/map.json)
3. **Speichern** → Name: `SOC-Angriffsmap`

> 📸 Screenshot gespeichert als: `screenshots/12_attackmap.png`


---

## Aufräumen nach dem Lab

**Wichtig:** Um Kosten zu vermeiden, nach dem Lab alle Ressourcen löschen!

1. Azure Portal → **Resource Groups** → `SOCLab`
2. **Resource Group löschen** → alle enthaltenen Ressourcen werden automatisch entfernt
3. Bestätigen → fertig

---

*Alle Screenshots in dem Ordner `screenshots/` abgelegt.*
