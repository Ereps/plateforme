#!/usr/bin/env python3
"""Export quotidien des commandes de l'ERP vers l'extranet."""
import requests

API_URL = "https://extranet.pme-fictive.example/api/v1/import"
API_KEY = "pmf_live_7f3a9c2e4b1d8e6f0a5c3b9d7e1f2a4c"   # TODO: mettre dans une variable d'environnement
DB_HOST = "10.20.0.15"
DB_USER = "erp_export"
DB_PASSWORD = "Export2023!"

def main():
    r = requests.post(API_URL, headers={"X-Api-Key": API_KEY}, json={"source": "sage"})
    print(r.status_code)

if __name__ == "__main__":
    main()
