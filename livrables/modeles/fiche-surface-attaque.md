<img src="../../assets/logo-carre.png" alt="Enseirb-Matmeca" width="110" align="right">

# Surface d'attaque exposée — <PME> — TLP:AMBER — <AAAA-MM-JJ>

*Gabarit du TP 1 (`seance1/tp.md`, partie B). Style fiche de CERT : concis, sourcé, actionnable. Date de rédaction en titre ; date des sources dans le journal. Exemple complet : `../exemple-fiche-surface-attaque.md`.*

## 1. Synthèse

*Cinq lignes maximum : l'organisation en quelques mots (activité, taille, domaine), les trois constats les plus importants nommés avec leur priorité, le niveau de risque global (faible, modéré, élevé, critique) et sa raison principale, une phrase sur ce qui n'a pas été fait (rien d'actif hors bac à sable, aucun identifiant testé).*

## 2. Périmètre identifié

*Une ligne par nom DNS, y compris ceux qui ne résolvent plus (c'est un constat). Source = outil ou fichier du pack ; confiance = cotation Admiralty à deux caractères (source A à F, information 1 à 6).*

| Nom | IP | Services (ports) | Technologies et versions | Source | Confiance |
|---|---|---|---|---|---|
| <domaine> | | | <MX, SPF, DMARC, WHOIS> | | |
| <sous-domaine> | | | | | |

*Une ligne sous le tableau : hébergeur(s), blocs d'adresses partagés, ce que cela implique.*

## 3. Constats par ordre de priorité

*Trois à six constats, classés par risque et non par ordre de découverte. Pour chacun, quatre éléments dans l'ordre : **Vu** (le fait, daté), **Risque** (ce qu'un attaquant en fait, pour cette organisation), **Source** (fichier ou URL, cotation), **Recommandation** (verbe d'action, délai, responsable). Les expositions sans CVE (secrets, accès distant, identifiants fuités) passent souvent avant les CVE.*

**C1 (<critique | haute | moyenne | faible>). <Titre en une ligne>.** Vu : … Risque : … Source : … Recommandation : …

**C2 (…). …**

## 4. Personnes et identifiants exposés

*Convention de nommage des adresses ; adresses présentes dans la fuite, anonymisées (`p.n***@domaine`), avec le rôle de la personne et non son nom ; la personne la plus exposée (nombre de sources publiques) ; recommandation. Rien sur la vie privée.*

## 5. Ce que nous n'avons pas fait et pourquoi

*Limites légales (aucune action active hors bac à sable, aucun identifiant testé, articles 323-1 et suivants du code pénal, charte), limites de temps, limites des données (Shodan daté, pas de vérification en direct, nuclei non exécuté), incohérences non tranchées entre sources.*

## 6. Journal de bord (annexe)

*Une ligne par action, dans l'ordre chronologique. Tout fait affirmé dans la fiche doit s'y retrouver.*

```
horodatage | action | outil | source (URL ou fichier) | résultat | cotation
<AAAA-MM-JJ HH:MM> | périmètre | crt.sh | <URL ou data/osint/crtsh.json> | <n noms, dates notables> | <A1>
```

## 7. Carte de la surface d'attaque (annexe)

*Image exportée (Maltego, draw.io ou photo d'un dessin) et légende de trois lignes qui dit ce que le tableau ne montre pas : nœuds partagés (deux noms sur une IP, IP dans le même bloc), chemins entre une personne exposée et un service, hôte isolé ou oublié.*

(image `<fichier>.png`) Légende : …

*Marquage TLP:AMBER : <une ligne : la fiche nomme une organisation et décrit des expositions exploitables ; qui peut la recevoir>.*

---

<img src="../../assets/logo-em.png" alt="Enseirb-Matmeca" width="160">

*César Lizurey · [cesar.lizurey.fr](https://cesar.lizurey.fr) · IT320 OSINT et Cyber Threat Intelligence, ENSEIRB-MATMECA*
