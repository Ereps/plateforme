#!/usr/bin/env python3
"""Lit un ou plusieurs journaux JSON Cowrie et crée un événement MISP « Honeypot Cowrie ».

Usage : cowrie-to-misp.py [fichier.json ...]   (défaut : /data/cowrie/cowrie.json et /data/cowrie/cowrie-24h-sample.json)
Attributs : ip-src (une par IP source, avec nombre de sessions), objet credential (login/mot de passe tentés),
            sha256 des fichiers téléchargés, url des téléchargements. Tags : tlp:green, source:honeypot.
"""
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

from misp_client import Misp, attr

files = [Path(p) for p in sys.argv[1:]] or [Path("/data/cowrie/cowrie.json"), Path("/data/cowrie/cowrie-24h-sample.json")]
ips, creds, hashes, urls = Counter(), Counter(), set(), set()
first_seen = defaultdict(lambda: None)

for f in files:
    if not f.exists():
        continue
    with f.open() as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            eid, ip = ev.get("eventid", ""), ev.get("src_ip")
            if eid == "cowrie.session.connect" and ip:
                ips[ip] += 1
                first_seen[ip] = first_seen[ip] or ev.get("timestamp")
            elif eid in ("cowrie.login.failed", "cowrie.login.success"):
                creds[(ev.get("username", ""), ev.get("password", ""))] += 1
            elif eid == "cowrie.session.file_download":
                if ev.get("shasum"):
                    hashes.add(ev["shasum"])
                if ev.get("url"):
                    urls.add(ev["url"])

if not ips:
    sys.exit("Aucune session Cowrie trouvée : lancez quelques connexions ssh -p 2222 root@localhost ou vérifiez data/cowrie/")

attributes = []
for ip, n in ips.most_common():
    attributes.append(attr("ip-src", ip, to_ids=n >= 3, comment=f"{n} sessions, premier contact {first_seen[ip]}"))
for h in sorted(hashes):
    attributes.append(attr("sha256", h, category="Payload delivery", to_ids=True, comment="fichier déposé sur le honeypot"))
for u in sorted(urls):
    attributes.append(attr("url", u, category="Payload delivery", to_ids=True, comment="téléchargement observé"))

objects = []
for (user, pwd), n in creds.most_common(50):
    objects.append({"name": "credential", "meta-category": "misc", "description": "Identifiant tenté sur le honeypot",
                    "Attribute": [
                        {"object_relation": "username", "type": "text", "value": user or "(vide)"},
                        {"object_relation": "password", "type": "text", "value": pwd or "(vide)", "comment": f"{n} tentatives"},
                    ]})

misp = Misp()
ev = misp.add_event(f"Honeypot Cowrie — {date.today().isoformat()}", attributes, tags=("tlp:green", "source:honeypot"), objects=objects)
print(f"Événement MISP #{ev['id']} créé : {len(attributes)} attributs, {len(objects)} objets credential, {len(ips)} IP sources")

# Corrélation rapide : quelles IP sont déjà connues d'un flux (ex. Feodo Tracker) ?
known = [ip for ip in ips if any(a.get("event_id") != ev["id"] for a in misp.search_attributes(ip))]
print("IP déjà présentes dans un autre événement (flux) :", ", ".join(known) or "aucune")
