#!/usr/bin/env python3
"""Génère le pack OSINT hors ligne du TP 1 dans plateforme/data/osint/.

Il reproduit, pour la PME fictive « PME Fictive SAS » (domaine pme-fictive.example, adresses IP
des plages de documentation RFC 5737), ce que les élèves obtiendraient en ligne : sortie crt.sh
(JSON), subfinder/dnsx, Shodan (JSON par IP), theHarvester, résultats de dorks, dépôt GitHub,
pages du site, WHOIS, Wayback, et les métadonnées d'une plaquette PDF.

Usage : python3 tools/make-osint-pack.py [graine]
Changer la graine (et quelques indices à la main) chaque année.
"""
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 2026)
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "osint"
OUT.mkdir(parents=True, exist_ok=True)

DOM = "pme-fictive.example"
ORG = "PME Fictive SAS"
IP_WEB = "203.0.113.10"      # www + extranet
IP_MAIL = "203.0.113.11"     # mail (Zimbra)
IP_DEV = "198.51.100.7"      # dev-old (Apache 2.4.49, HTTP)
TODAY = datetime(2026, 10, 20)


def d(days_ago):
    return (TODAY - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


# 1. crt.sh ---------------------------------------------------------------------------------------
certs = []
cid = 11854400000
for name, ago, days in [("www", 40, 90), ("www", 130, 90), ("extranet", 40, 90), ("extranet", 130, 90),
                        ("mail", 55, 90), ("autodiscover", 55, 90), ("dev-old", 548, 90), ("vpn", 700, 90), ("www", 220, 90)]:
    cid += random.randint(1000, 90000)
    certs.append({
        "issuer_ca_id": 295815, "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": f"{name}.{DOM}", "name_value": f"{name}.{DOM}",
        "id": cid, "entry_timestamp": d(ago), "not_before": d(ago), "not_after": d(ago - days),
        "serial_number": "%032x" % random.getrandbits(128), "result_count": 1,
    })
(OUT / "crtsh.json").write_text(json.dumps(sorted(certs, key=lambda c: c["not_before"], reverse=True), indent=1))

# 2. subfinder / dnsx ----------------------------------------------------------------------------
(OUT / "subfinder.txt").write_text("\n".join(f"{n}.{DOM}" for n in ["www", "extranet", "mail", "autodiscover", "dev-old", "vpn"]) + "\n")
(OUT / "dnsx.txt").write_text(
    f"www.{DOM} [A] [{IP_WEB}]\nextranet.{DOM} [A] [{IP_WEB}]\nmail.{DOM} [A] [{IP_MAIL}]\n"
    f"autodiscover.{DOM} [CNAME] [mail.{DOM}]\ndev-old.{DOM} [A] [{IP_DEV}]\n"
    f"# vpn.{DOM} : NXDOMAIN (aucune résolution)\n")
(OUT / "dns-records.txt").write_text(
    f"; dig {DOM} ANY (extrait)\n{DOM}.\t3600\tIN\tA\t{IP_WEB}\n{DOM}.\t3600\tIN\tMX\t10 mail.{DOM}.\n"
    f"{DOM}.\t3600\tIN\tTXT\t\"v=spf1 mx ip4:{IP_MAIL} include:spf.protection.outlook.com -all\"\n"
    f"{DOM}.\t3600\tIN\tNS\tns1.registrar-fictif.example.\n_dmarc.{DOM}.\t3600\tIN\tTXT\t\"v=DMARC1; p=none; rua=mailto:postmaster@{DOM}\"\n")

# 3. Shodan ----------------------------------------------------------------------------------------
shodan = {
    IP_WEB: {"ip_str": IP_WEB, "org": "Hebergeur Fictif SAS", "asn": "AS64496", "country_code": "FR", "city": "Bordeaux",
             "last_update": d(6), "hostnames": [f"www.{DOM}", f"extranet.{DOM}"], "ports": [443, 3389, 80],
             "data": [
                 {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0", "ssl": {"cert": {"subject": {"CN": f"www.{DOM}"}}},
                  "http": {"title": "PME Fictive SAS - Usinage de précision", "server": "nginx/1.24.0"}},
                 {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24.0", "http": {"title": "301 Moved Permanently", "location": f"https://www.{DOM}/"}},
                 {"port": 3389, "transport": "tcp", "product": "Remote Desktop Protocol", "data": "Remote Desktop Protocol\nNTLM: Target_Name: EXTRANET\nNetBIOS_Computer_Name: EXTRANET-SRV\nProduct_Version: 10.0.14393 (Windows Server 2016)\n", "os": "Windows Server 2016", "vulns": []},
             ]},
    IP_MAIL: {"ip_str": IP_MAIL, "org": "Hebergeur Fictif SAS", "asn": "AS64496", "country_code": "FR", "city": "Bordeaux",
              "last_update": d(9), "hostnames": [f"mail.{DOM}"], "ports": [25, 443, 587, 993],
              "data": [
                  {"port": 25, "transport": "tcp", "product": "Postfix smtpd", "data": f"220 mail.{DOM} ESMTP Postfix\n"},
                  {"port": 443, "transport": "tcp", "product": "nginx", "http": {"title": "Zimbra Web Client Sign In", "server": "nginx"}},
                  {"port": 587, "transport": "tcp", "product": "Postfix smtpd"}, {"port": 993, "transport": "tcp", "product": "Dovecot imapd"},
              ]},
    IP_DEV: {"ip_str": IP_DEV, "org": "Hebergeur Fictif SAS", "asn": "AS64496", "country_code": "FR", "city": "Bordeaux",
             "last_update": d(17), "hostnames": [f"dev-old.{DOM}"], "ports": [80, 22],
             "data": [
                 {"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.49",
                  "http": {"title": "Index of /", "server": "Apache/2.4.49 (Unix)", "robots": "User-agent: *\nDisallow: /backup/\nDisallow: /admin/\nDisallow: /old-site/\n"},
                  "vulns": {"CVE-2021-41773": {"cvss": 7.5, "summary": "Path traversal and file disclosure in Apache HTTP Server 2.4.49", "verified": False},
                            "CVE-2021-42013": {"cvss": 9.8, "summary": "Path traversal fix bypass in 2.4.49 and 2.4.50", "verified": False}}},
                 {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.6p1 Ubuntu-4ubuntu0.7", "data": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\n"},
             ]},
}
for ip, obj in shodan.items():
    (OUT / f"shodan-{ip}.json").write_text(json.dumps(obj, indent=1, ensure_ascii=False))

# 4. Site web (pages publiques) ---------------------------------------------------------------------
site = OUT / "site"
site.mkdir(exist_ok=True)
(site / "index.html").write_text(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>PME Fictive SAS - Usinage de précision</title>
<meta name="generator" content="WordPress 6.4.2"></head><body>
<h1>PME Fictive SAS</h1><p>Usinage de précision pour l'aéronautique et le médical, 120 salariés, Mérignac (33).</p>
<p>Certifiée EN 9100. Clients : grands donneurs d'ordre aéronautiques de la région.</p>
<nav><a href="equipe.html">Équipe</a> · <a href="recrutement.html">Recrutement</a> · <a href="plaquette.pdf">Plaquette</a> · <a href="https://extranet.{DOM}/">Extranet clients</a></nav>
</body></html>""")
(site / "equipe.html").write_text(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Équipe - PME Fictive SAS</title></head><body>
<h1>Notre équipe</h1>
<ul>
<li>Marie Durand, directrice générale : marie.durand@{DOM}</li>
<li>Thomas Lefebvre, responsable informatique : thomas.lefebvre@{DOM}</li>
<li>Karim Benali, responsable comptable et achats : karim.benali@{DOM}</li>
<li>Standard : contact@{DOM} · 05 56 00 00 00</li>
</ul></body></html>""")
(site / "recrutement.html").write_text(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Recrutement - PME Fictive SAS</title></head><body>
<h1>Administrateur systèmes et réseaux (H/F) - CDI - Mérignac</h1>
<p>Publié le 12 septembre 2026. Rattaché au responsable informatique, vous administrez notre parc : 60 postes Windows 10/11,
serveurs Windows Server 2016 et 2019 (AD, fichiers, ERP Sage), messagerie Zimbra hébergée, pare-feu Fortinet FortiGate 60F,
sauvegardes Veeam, accès distant RDP pour les commerciaux. Expérience Fortinet et Zimbra souhaitée. Candidature : thomas.lefebvre@{DOM}.</p>
</body></html>""")
(site / "robots-dev-old.txt").write_text("User-agent: *\nDisallow: /backup/\nDisallow: /admin/\nDisallow: /old-site/\n")
(site / "plaquette-metadonnees.txt").write_text("""$ exiftool plaquette.pdf
File Name                       : plaquette.pdf
File Size                       : 2.1 MB
PDF Version                     : 1.7
Creator                         : Adobe InDesign 18.5 (Windows)
Producer                        : Adobe PDF Library 17.0
Author                          : k.benali
Title                           : Plaquette PME Fictive 2023
Create Date                     : 2023:04:11 10:42:17+02:00
Modify Date                     : 2023:04:12 09:03:40+02:00
Subject                         : D:\\Partage\\Communication\\plaquette-2023-v3.indd
""")

# 5. theHarvester ------------------------------------------------------------------------------
(OUT / "theharvester.txt").write_text(f"""*******************************************************************
* theHarvester 4.11.1 (sortie figée, sources : certspotter, crtsh, duckduckgo, hackertarget)
*******************************************************************
[*] Target: {DOM}

[*] Emails found: 4
---------------------
contact@{DOM}
karim.benali@{DOM}
marie.durand@{DOM}
thomas.lefebvre@{DOM}

[*] Hosts found: 5
---------------------
autodiscover.{DOM}:{IP_MAIL}
dev-old.{DOM}:{IP_DEV}
extranet.{DOM}:{IP_WEB}
mail.{DOM}:{IP_MAIL}
www.{DOM}:{IP_WEB}
""")

# 6. Dorks et moteurs --------------------------------------------------------------------------
(OUT / "dorks-resultats.txt").write_text(f"""Résultats figés (moteur de recherche, 20 octobre 2026)

site:{DOM} filetype:pdf
  1. https://www.{DOM}/plaquette.pdf — « Plaquette PME Fictive 2023 » (métadonnées : voir site/plaquette-metadonnees.txt)
  2. https://www.{DOM}/qualite/certificat-en9100.pdf — certificat EN 9100 (valide jusqu'en 2027)

"{DOM}" password
  aucun résultat

"pme-fictive" github
  1. https://github.com/pme-fictive/outils-extranet — « Scripts d'export ERP vers l'extranet » (voir github-repo/)

site:{DOM} intitle:"index of"
  1. http://dev-old.{DOM}/ — « Index of / » (backup/, admin/, old-site/)

"PME Fictive SAS" linkedin
  1. Page entreprise : 118 abonnés, 43 salariés déclarés ; 3 publications en 2026 (nouvelle machine 5 axes, salon du Bourget, recrutement admin sys)
  2. Profil « Thomas L. » — Responsable informatique chez PME Fictive SAS — « Fortinet NSE 4, Zimbra, Windows Server »
""")

# 7. Dépôt GitHub ------------------------------------------------------------------------------
repo = OUT / "github-repo" / "outils-extranet"
repo.mkdir(parents=True, exist_ok=True)
(repo / "README.md").write_text(f"# outils-extranet\n\nScripts internes d'export de l'ERP vers l'extranet clients (https://extranet.{DOM}/).\n\nAuteur : T. Lefebvre. Ne pas diffuser.\n")
(repo / "export_erp.py").write_text(f'''#!/usr/bin/env python3
"""Export quotidien des commandes de l'ERP vers l'extranet."""
import requests

API_URL = "https://extranet.{DOM}/api/v1/import"
API_KEY = "pmf_live_7f3a9c2e4b1d8e6f0a5c3b9d7e1f2a4c"   # TODO: mettre dans une variable d'environnement
DB_HOST = "10.20.0.15"
DB_USER = "erp_export"
DB_PASSWORD = "Export2023!"

def main():
    r = requests.post(API_URL, headers={{"X-Api-Key": API_KEY}}, json={{"source": "sage"}})
    print(r.status_code)

if __name__ == "__main__":
    main()
''')
(repo / "config.example.ini").write_text(f"[extranet]\nurl = https://extranet.{DOM}\nrdp_host = extranet.{DOM}:3389\n\n[mail]\nsmtp = mail.{DOM}:587\n")
(repo / "COMMITS.txt").write_text("""git log --oneline (extrait)
a41c2f0 2026-06-03 T. Lefebvre  fix export encoding
9b7e1d4 2025-11-18 T. Lefebvre  add RDP host to config example
3c0f8aa 2025-02-07 T. Lefebvre  initial commit (clé API en dur, à corriger)
""")

# 8. WHOIS / RDAP, Wayback ----------------------------------------------------------------------
(OUT / "whois.txt").write_text(f"""domain:      {DOM}
registrar:   Registrar Fictif SAS
created:     2014-03-18
expires:     2027-03-18
nserver:     ns1.registrar-fictif.example
nserver:     ns2.registrar-fictif.example
holder:      PME FICTIVE SAS (données de contact masquées, RGPD)
tech-c:      TL123-FICTIF (Thomas Lefebvre)
""")
(OUT / "wayback.txt").write_text(f"""Wayback Machine — captures de http://dev-old.{DOM}/ (extrait)
2021-09-14  Index of /  — backup/ (pme-fictive-site-2021.tar.gz, 48 Mo), admin/ (phpMyAdmin 4.9), old-site/
2023-01-02  Index of /  — identique
2025-04-30  Index of /  — identique

Captures de https://www.{DOM}/equipe.html
2022-05-10  quatre personnes (dont « Paul Martin, responsable informatique, paul.martin@{DOM} »)
2024-09-03  trois personnes (Thomas Lefebvre remplace Paul Martin)
""")

# 9. Index du pack --------------------------------------------------------------------------------
(OUT / "README.md").write_text(f"""<img src="../../assets/logo-carre.png" alt="Enseirb-Matmeca" width="110" align="right">

# Pack OSINT hors ligne — TP 1 (PME Fictive SAS, {DOM})

Sorties figées, générées par `tools/make-osint-pack.py`, à utiliser quand le domaine bac à sable n'est pas disponible
(ou comme corrigé figé). Toutes les adresses IP sont dans les plages de documentation (RFC 5737) et ne joignent rien.

| Étape du TP | Fichier(s) | Ce que l'élève y fait |
|---|---|---|
| A1 périmètre | `crtsh.json`, `subfinder.txt`, `dnsx.txt`, `dns-records.txt`, `whois.txt`, `wayback.txt` | sous-domaines, dates des certificats, ce qui ne résout plus |
| A2 exposition | `shodan-<ip>.json` (3 fichiers) | ports, bannières, versions, CVE suggérées |
| A3 personnes | `site/equipe.html`, `site/recrutement.html`, `theharvester.txt`, `../fuite-simulee.txt` | convention de nommage, adresses dans la fuite, technologies |
| A4 code et documents | `github-repo/`, `dorks-resultats.txt`, `site/plaquette-metadonnees.txt`, `site/robots-dev-old.txt` | secrets, architecture, métadonnées |

Lire un JSON crt.sh : `jq -r '.[].name_value' crtsh.json | sort -u`. Lire un JSON Shodan : `jq '.data[] | {{port, product, version}}' shodan-{IP_DEV}.json`.

---

<img src="../../assets/logo-em.png" alt="Enseirb-Matmeca" width="160">

*César Lizurey · [cesar.lizurey.fr](https://cesar.lizurey.fr) · IT320 OSINT et Cyber Threat Intelligence, ENSEIRB-MATMECA*
""")
print(f"Pack OSINT hors ligne généré dans {OUT} ({sum(1 for _ in OUT.rglob('*') if _.is_file())} fichiers)")
