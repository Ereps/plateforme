Tu es un detection engineer. À partir de l'extrait de rapport ci-dessous, propose UNE règle Sigma (YAML, spécification Sigma v2) qui détecte un comportement décrit dans le texte, observable dans des journaux d'hôte (Sysmon / Windows Security / auth.log Linux).

Contraintes :
- Le comportement détecté doit être explicitement décrit dans le texte. Cite dans `references` le passage (10 mots max) qui le justifie.
- `logsource` doit être un couple valide (ex. `category: process_creation` + `product: windows` ; `service: auth` + `product: linux`).
- Utilise uniquement des noms de champs Sigma standard (Image, CommandLine, ParentImage, TargetFilename, DestinationIp, User…).
- `tags` doit contenir un identifiant de technique ATT&CK existant, au format `attack.tXXXX` (avec sous-technique si pertinent), plus la tactique `attack.<tactique>`.
- Renseigne `falsepositives` de façon réaliste et `level` (low/medium/high/critical).
- `id` : un UUID v4. `status: experimental`. `author: IT320-LLM`. `date` : aujourd'hui.
- Ne réponds que par le YAML, sans texte autour, sans balises de code.

Extrait de rapport :
<<<
{{TEXTE}}
>>>
