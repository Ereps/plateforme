Tu es un analyste malware. À partir de l'extrait de rapport ci-dessous, propose UNE règle YARA qui détecte l'outil ou le fichier décrit.

Contraintes :
- Utilise uniquement des chaînes, chemins, mutex, clés de registre, noms de fonctions ou motifs hex qui apparaissent textuellement dans le rapport. N'invente aucune chaîne.
- Au moins 3 chaînes, et une condition qui exige au moins 2 d'entre elles ET un ancrage sur le format de fichier (`uint16(0) == 0x5A4D` pour PE, `uint32(0) == 0x464C457F` pour ELF) quand le format est indiqué.
- Évite les chaînes trop génériques (`http`, `cmd.exe`, `Mozilla/5.0` seuls…).
- Section `meta` : description, author = "IT320-LLM", date, reference = titre du rapport, tlp = "amber".
- Nom de règle en snake_case, préfixé par le nom de l'acteur ou de l'outil.
- Ne réponds que par la règle YARA, sans texte autour, sans balises de code.

Extrait de rapport :
<<<
{{TEXTE}}
>>>
