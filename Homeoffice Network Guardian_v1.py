# ==========================================================
# HomeOffice Network Guardian
#
# Version : 1.0
# Autor   : Dominique Heilig
#
# Beschreibung:
# Der HomeOffice Network Guardian analysiert
# sicherheitsrelevante Windows- und Netzwerkeinstellungen,
# bewertet potenzielle Risiken und berechnet daraus
# einen Security Score mit konkreten
# Handlungsempfehlungen.
#
# Ziel:
# Unterstützung von Mitarbeitenden und
# der Sicherheit eines Homeoffice-Arbeitsplatzes.

import socket
import subprocess

# ==========================
# Variablen
# ==========================

score = 0

risiken = []
empfehlungen = []

# ==========================
# Kopfbereich
# ==========================

print("===================================")
print(" HomeOffice Network Guardian")
print("===================================")

# ==========================
# Computername & IP-Adresse
# ==========================

computername = socket.gethostname()
ip_adresse = socket.gethostbyname(computername)

print("Computername:", computername)
print("IP-Adresse:", ip_adresse)

# ==========================
# Netzwerkadapter
# ==========================

print("\n--- Netzwerkadapter ---")

ergebnis = subprocess.run(
    ["netsh", "interface", "show", "interface"],
    capture_output=True,
    text=True
)

print(ergebnis.stdout)

# ==========================
# Verbindungstyp
# ==========================

print("\n--- Verbindungstyp ---")

if "WLAN" in ergebnis.stdout and "Verbunden" in ergebnis.stdout:

    score += 10

    print("[INFO] Sie sind aktuell über WLAN verbunden.")
    print("[EMPFEHLUNG] Achten Sie auf WPA2/WPA3 und nutzen Sie bei Firmendaten ein VPN.")

elif "Ethernet" in ergebnis.stdout and "Verbunden" in ergebnis.stdout:

    score += 10

    print("[INFO] Sie sind aktuell über LAN verbunden.")
    print("[OK] LAN ist meist stabiler und sicherer als öffentliches WLAN.")

else:

    risiken.append("Keine aktive Netzwerkverbindung erkannt.")
    empfehlungen.append("Netzwerkverbindung prüfen.")

    print("[WARNUNG] Keine aktive Netzwerkverbindung erkannt.")

# ==========================
# VPN Check
# ==========================

print("\n--- VPN-Check ---")

vpn_gefunden = False

vpn_woerter = [
    "VPN",
    "WireGuard",
    "OpenVPN",
    "Cisco",
    "Fortinet",
    "AnyConnect",
    "Nord",
    "Proton"
]

for wort in vpn_woerter:

    if wort.lower() in ergebnis.stdout.lower():
        vpn_gefunden = True

if vpn_gefunden:

    score += 30

    print("[OK] VPN-Adapter erkannt.")

else:

    print("[WARNUNG] Kein VPN-Adapter erkannt.")
    print("[EMPFEHLUNG] Bei Zugriff auf Unternehmensdaten sollte ein Firmen-VPN genutzt werden.")

    risiken.append("Kein VPN erkannt.")
    empfehlungen.append("Bei Zugriff auf Unternehmensdaten sollte ein Firmen-VPN genutzt werden.")

# ==========================
# Firewall Check
# ==========================

print("\n--- Firewall-Check ---")

firewall = subprocess.run(
    ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"],
    capture_output=True,
    text=True
)

if "False" in firewall.stdout:

    print("[WARNUNG] Mindestens ein Firewall-Profil ist deaktiviert.")

    risiken.append("Firewall nicht vollständig aktiv.")
    empfehlungen.append("Windows-Firewall für alle Profile aktivieren.")

else:

    score += 25

    print("[OK] Die Windows-Firewall ist aktiv.")

# ==========================
# Netzwerkprofil
# ==========================

print("\n--- Netzwerkprofil-Check ---")

profil = subprocess.run(
    ["powershell", "-Command", "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"],
    capture_output=True,
    text=True
)

netzwerkprofil = profil.stdout.strip()

print("Netzwerkprofil:", netzwerkprofil)

if "Public" in netzwerkprofil:

    score += 20

    print("[OK] Öffentliches Netzwerkprofil aktiv.")
    print("[INFO] Das öffentliche Profil blockiert mehr eingehende Verbindungen.")

elif "Private" in netzwerkprofil:

    score += 15

    print("[INFO] Privates Netzwerkprofil aktiv.")

else:

    risiken.append("Netzwerkprofil unbekannt.")
    empfehlungen.append("Netzwerkprofil prüfen.")

# ==========================
# DNS Check
# ==========================

print("\n--- DNS-Check ---")

dns = subprocess.run(
    ["powershell", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"],
    capture_output=True,
    text=True
)

dns_server = dns.stdout.strip()

if dns_server:

    score += 5

    print("[INFO] Erkannte DNS-Server:")
    print(dns_server)

else:

    risiken.append("DNS-Server konnten nicht erkannt werden.")
    empfehlungen.append("DNS-Konfiguration prüfen.")

# ==========================
# Router / Gateway Check
# ==========================

print("\n--- Router/Gateway-Check ---")

gateway = subprocess.run(
    ["powershell", "-Command", "(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4DefaultGateway.NextHop"],
    capture_output=True,
    text=True
)

gateway_adresse = gateway.stdout.strip()

if gateway_adresse:

    score += 10

    print("[INFO] Erkannter Router/Gateway:", gateway_adresse)

else:

    risiken.append("Kein Gateway erkannt.")
    empfehlungen.append("Netzwerkverbindung prüfen.")

# ==========================
# Security Score
# ==========================

print("\n===============================")
print("      SECURITY SCORE")
print("===============================")

print(f"\nGesamtbewertung: {score}/100")

if score >= 80:
    print("🟢 Niedriges Risiko")
elif score >= 50:
    print("🟡 Mittleres Risiko")
else:
    print("🔴 Hohes Risiko")

print("\nPunkteübersicht:")

if "WLAN" in ergebnis.stdout and "Verbunden" in ergebnis.stdout:
    print(" +10 WLAN-Verbindung erkannt")

if vpn_gefunden:
    print(" +30 VPN erkannt")
else:
    print("  +0 VPN nicht erkannt")

if "False" not in firewall.stdout:
    print(" +25 Firewall aktiv")

if "Public" in netzwerkprofil:
    print(" +20 Öffentliches Netzwerkprofil")

elif "Private" in netzwerkprofil:
    print(" +15 Privates Netzwerkprofil")

if dns_server:
    print(" +5 DNS erkannt")

if gateway_adresse:
    print(" +10 Gateway erkannt")

# ==========================
# Zusammenfassung
# ==========================

print("\n--- Zusammenfassung ---")

if len(risiken) == 0:

    print("[OK] Keine kritischen Risiken erkannt.")

else:

    print("Gefundene Risiken:")

    for risiko in risiken:
        print("-", risiko)

if len(empfehlungen) > 0:

    print("\nEmpfehlungen:")

    for empfehlung in empfehlungen:
        print("-", empfehlung)

else:

    print("\n[OK] Keine zusätzlichen Empfehlungen.")

# ==========================
# Security Report
# ==========================

report = open("security_report.txt", "w")

report.write("HomeOffice Network Guardian Report\n")
report.write("==================================\n\n")

report.write("Computername: ")
report.write(computername)
report.write("\n")

report.write("IP-Adresse: ")
report.write(ip_adresse)
report.write("\n\n")

report.write("Security Score: ")
report.write(str(score))
report.write("/100\n\n")

report.write("Gefundene Risiken:\n")

if len(risiken) == 0:
    report.write("Keine Risiken gefunden.\n")

else:
    for risiko in risiken:
        report.write("- ")
        report.write(risiko)
        report.write("\n")

report.write("\nEmpfehlungen:\n")

if len(empfehlungen) == 0:
    report.write("Keine Empfehlungen.\n")

else:
    for empfehlung in empfehlungen:
        report.write("- ")
        report.write(empfehlung)
        report.write("\n")

report.write("\nNaechster empfohlener Schritt:\n")

if vpn_gefunden == False:

    report.write("Firmen-VPN aktivieren.\n")
    report.write("Ein VPN verschluesselt die Verbindung.\n")
    report.write("Unternehmensdaten werden dadurch besser geschuetzt.\n")
    report.write("Moeglicher Security Score: ")
    report.write(str(score + 30))
    report.write("/100\n")

else:

    report.write("Aktuell kein weiterer Schritt erforderlich.\n")

report.close()

print("\n[OK] Sicherheitsbericht wurde erstellt.")

print("\n[OK] Sicherheitsbericht wurde erstellt.")


# ==========================
# Nächster empfohlener Schritt
# ==========================

print("\n--- Nächster empfohlener Schritt ---")

if not vpn_gefunden:
    print("Firmen-VPN aktivieren.")
    print("Begründung: Ein VPN verschlüsselt die Verbindung zwischen Homeoffice-Laptop und Unternehmensnetzwerk.")
    print("Nutzen: Unternehmensdaten sind unterwegs besser vor Mitlesen und Manipulation geschützt.")
    print("Möglicher Score nach Aktivierung des VPN: " + str(score + 30) + "/100")
    print("Hinweis: Ein VPN ersetzt keine Firewall, keine Updates und keine sicheren Passwörter.")
else:
    print("Aktuell kein dringender Netzwerk-Schritt erforderlich.")
    
# ==========================
# Abschluss
# ==========================

print("\n===================================")
print(" Analyse erfolgreich abgeschlossen")
print("===================================")

print("Bericht gespeichert unter: security_report.txt")
print("Version: HomeOffice Network Guardian 1.0")
print("Status: Projekt-MVP fertig")