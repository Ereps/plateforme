"""Client MISP minimal (REST, sans dépendance à PyMISP) partagé par les scripts IT320."""
import os
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _env_bool(name, default):
    """Lit une variable d'environnement booléenne ("true"/"false"/"1"/"0"/"yes"/"no")."""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Misp:
    def __init__(self, url=None, key=None, verify=None):
        # MISP_URL (nom du service Compose, ex. https://misp-nginx:8443) prime sur MISP_BASEURL (adresse vue du poste).
        self.url = (url or os.environ.get("MISP_URL") or os.environ.get("MISP_BASEURL", "https://localhost:8443")).rstrip("/")
        self.key = key or os.environ.get("MISP_API_KEY")
        if not self.key:
            sys.exit("MISP_API_KEY manquant (voir .env)")
        # MISP_VERIFY_SSL=false (défaut) : certificat auto-signé du MISP du groupe.
        if verify is None:
            verify = _env_bool("MISP_VERIFY_SSL", False)
        self.s = requests.Session()
        self.s.headers.update({"Authorization": self.key, "Accept": "application/json", "Content-Type": "application/json"})
        self.s.verify = verify

    def add_event(self, info, attributes, tags=(), objects=(), distribution=0, threat_level=3, analysis=0):
        body = {"Event": {
            "info": info, "distribution": distribution, "threat_level_id": threat_level, "analysis": analysis,
            "Attribute": list(attributes), "Object": list(objects), "Tag": [{"name": t} for t in tags],
        }}
        r = self.s.post(f"{self.url}/events/add", json=body, timeout=60)
        r.raise_for_status()
        return r.json()["Event"]

    def search_attributes(self, value):
        r = self.s.post(f"{self.url}/attributes/restSearch", json={"value": value, "returnFormat": "json"}, timeout=60)
        r.raise_for_status()
        return r.json().get("response", {}).get("Attribute", [])


def attr(type_, value, category="Network activity", to_ids=False, comment=""):
    return {"type": type_, "category": category, "value": value, "to_ids": to_ids, "comment": comment}


# Catégorie MISP attendue pour chaque type d'attribut usuel (un hash n'est pas de la « Network activity »).
CATEGORY_BY_TYPE = {
    "md5": "Payload delivery", "sha1": "Payload delivery", "sha256": "Payload delivery",
    "vulnerability": "External analysis", "link": "External analysis",
    "ip-dst": "Network activity", "ip-src": "Network activity", "domain": "Network activity",
    "hostname": "Network activity", "url": "Network activity", "email-src": "Payload delivery",
}


def attack_tag(attack_id, name=None):
    """Tag MISP pour un identifiant ATT&CK.

    Technique (Txxxx[.yyy]) avec nom connu  -> misp-galaxy:mitre-attack-pattern="Nom - T1234" (galaxie reconnue par MISP)
    Technique sans nom                       -> attack:T1234 (tag simple, pas de galaxie : MISP n'accepte pas l'identifiant seul)
    Tactique (TAxxxx)                        -> attack-tactic:TA0001 (tag simple)
    """
    attack_id = str(attack_id).strip().upper()
    if attack_id.startswith("TA"):
        return f"attack-tactic:{attack_id}"
    if name:
        return f'misp-galaxy:mitre-attack-pattern="{name} - {attack_id}"'
    return f"attack:{attack_id}"
