# Sorties LLM précalculées — TP 3 (plan B si Ollama est indisponible)

Même principe que pour le TP 2 : sorties typiques d'un 7B, défauts compris, à tester et à corriger comme si elles sortaient du workflow.

- `silex7-loaderx-ia.yar` : compile ; mais `$s3` (`Mozilla/5.0`) est trop générique et `2 of them` peut matcher des fichiers sains qui
  contiennent « LoaderX » et un User-Agent ; `$s2` reprend le mutex avec un double antislash à vérifier. Tester sur `data/samples/` et `data/corpus-sain/`.
- `silex7-powershell-ia.yml` : correcte dans l'esprit ; `-enc` en `contains` attrape aussi `-encoding` (faux positifs possibles) ; pas de
  filtre sur `WindowStyle hidden` pourtant décrit dans le rapport. Tester avec `sigma-test.py` sur `data/logs/`.
- `attack-ia.json` : 8 techniques justes, **T1003.001 inféré** (non décrit dans le rapport) et **T1071.001 hors liste** de candidats :
  précision 8/10, rappel 8/8 par rapport à la référence du rapport.

Copier ces fichiers dans `out/ia/` pour dérouler la partie B du TP 3 sans LLM.
