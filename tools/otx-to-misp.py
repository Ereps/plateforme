#!/usr/bin/env python3
"""Crée un événement MISP par pulse AlienVault OTX récent correspondant aux mots-clés OTX_KEYWORDS (.env).

Usage : otx-to-misp.py [--max 5]
"""
import argparse
import os
import sys
import requests

from misp_client import CATEGORY_BY_TYPE, Misp, attack_tag, attr

OTX = "https://otx.alienvault.com/api/v1"
TYPE_MAP = {"IPv4": "ip-dst", "IPv6": "ip-dst", "domain": "domain", "hostname": "hostname", "URL": "url",
            "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256", "email": "email-src", "CVE": "vulnerability"}

ap = argparse.ArgumentParser()
ap.add_argument("--max", type=int, default=5)
args = ap.parse_args()

key = os.environ.get("OTX_API_KEY")
if not key:
    sys.exit("OTX_API_KEY manquant (créez un compte gratuit sur otx.alienvault.com)")
keywords = [k.strip() for k in os.environ.get("OTX_KEYWORDS", "ransomware").split(",") if k.strip()]
s = requests.Session()
s.headers["X-OTX-API-KEY"] = key
misp = Misp()

created = 0
for kw in keywords:
    r = s.get(f"{OTX}/search/pulses", params={"q": kw, "sort": "-modified", "limit": args.max}, timeout=60)
    r.raise_for_status()
    for p in r.json().get("results", []):
        if created >= args.max:
            break
        ind = s.get(f"{OTX}/pulses/{p['id']}/indicators", timeout=60).json().get("results", [])
        attributes = [attr(TYPE_MAP[i["type"]], i["indicator"], category=CATEGORY_BY_TYPE.get(TYPE_MAP[i["type"]], "Network activity"),
                           to_ids=False, comment=i.get("description") or "")
                      for i in ind if i["type"] in TYPE_MAP][:200]
        attributes.append(attr("link", f"https://otx.alienvault.com/pulse/{p['id']}", category="External analysis"))
        # attack_ids OTX : liste de dicts {"id": "T1566", "name": "Phishing", ...} (parfois de simples chaînes sur d'anciens pulses)
        tags = ["tlp:" + (p.get("tlp") or "green"), "source:otx"]
        for t in p.get("attack_ids", [])[:20]:
            if isinstance(t, dict):
                tags.append(attack_tag(t.get("id", ""), t.get("name")))
            else:
                tags.append(attack_tag(t))
        tags = [t for t in tags if not t.endswith(":")]
        ev = misp.add_event(f"[OTX] {p['name']}", attributes, tags=tags)
        created += 1
        print(f"#{ev['id']} {p['name']} — {len(attributes)} attributs")
print(f"{created} événement(s) créé(s)")
