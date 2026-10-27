<img src="../../assets/logo-carre.png" alt="Enseirb-Matmeca" width="110" align="right">

# Pack OSINT hors ligne — TP 1 (PME Fictive SAS, pme-fictive.example)

Sorties figées, générées par `tools/make-osint-pack.py`, à utiliser quand le domaine bac à sable n'est pas disponible
(ou comme corrigé figé). Toutes les adresses IP sont dans les plages de documentation (RFC 5737) et ne joignent rien.

| Étape du TP | Fichier(s) | Ce que l'élève y fait |
|---|---|---|
| A1 périmètre | `crtsh.json`, `subfinder.txt`, `dnsx.txt`, `dns-records.txt`, `whois.txt`, `wayback.txt` | sous-domaines, dates des certificats, ce qui ne résout plus |
| A2 exposition | `shodan-<ip>.json` (3 fichiers) | ports, bannières, versions, CVE suggérées |
| A3 personnes | `site/equipe.html`, `site/recrutement.html`, `theharvester.txt`, `../fuite-simulee.txt` | convention de nommage, adresses dans la fuite, technologies |
| A4 code et documents | `github-repo/`, `dorks-resultats.txt`, `site/plaquette-metadonnees.txt`, `site/robots-dev-old.txt` | secrets, architecture, métadonnées |

Lire un JSON crt.sh : `jq -r '.[].name_value' crtsh.json | sort -u`. Lire un JSON Shodan : `jq '.data[] | {port, product, version}' shodan-198.51.100.7.json`.

---

<img src="../../assets/logo-em.png" alt="Enseirb-Matmeca" width="160">

*César Lizurey · [cesar.lizurey.fr](https://cesar.lizurey.fr) · IT320 OSINT et Cyber Threat Intelligence, ENSEIRB-MATMECA*
