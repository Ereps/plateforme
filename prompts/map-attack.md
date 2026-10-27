Tu es un analyste CTI. À partir du rapport ci-dessous, identifie les techniques MITRE ATT&CK (Enterprise) décrites.

Contraintes :
- Choisis UNIQUEMENT parmi la liste fermée de techniques candidates fournie ci-dessous (identifiant et nom). Ne propose aucun identifiant absent de cette liste.
- Pour chaque technique retenue, cite le passage du rapport (15 mots max) qui la justifie et donne une confiance (high/medium/low).
- Si un comportement n'a pas de technique candidate correspondante, signale-le dans "unmapped" plutôt que de forcer un identifiant.
- Réponds uniquement par un objet JSON valide :

{
  "techniques": [{"id": "T1059.001", "name": "…", "evidence": "…", "confidence": "high|medium|low"}],
  "unmapped": ["comportement décrit sans technique candidate"]
}

Techniques candidates :
{{CANDIDATS}}

Rapport :
<<<
{{TEXTE}}
>>>
