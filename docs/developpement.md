# Construction locale

Les compilations de livraison sont locales, sans Actions ni runner. scripts/build-agent-binaries.py produit PJSIP2.16 et les wheels amont verrouillés ; scripts/prepare-agent-public-runtime.py transforme ensuite le SDK pour utiliser les runtimes Fortran/quadmath système et ajoute les notices. scripts/package-agent-release.py assemble les sources Agent, les SDK et l’image seule, depuis des sources propres.

Les gates Docker Desktop/controlled-build sont des garde-fous du processus de publication, pas un prérequis client. Un contributeur peut étudier/modifier/reconstruire les sources selon leurs licences ; aucune compilation n’est lancée par le parcours d’installation standard. La signature privée WIFX n’est pas fournie. Une compilation personnelle nécessite sa propre source HTTPS et racine de confiance.
