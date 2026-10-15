# Docker Linux AMD64

Docker local actif et accès administrateur au socket Unix. Aucun registry privé ou GHCR n’est requis : l’archive Agent seule est téléchargée depuis GitHub, vérifiée puis importée par ID immuable. Aucun pull implicite.

L’installateur crée seulement l’Agent concerné, utilise le réseau host pour SIP/RTP, vérifie les ports et conserve un répertoire persistant dédié. Il fonctionne même sans Compose. Le conteneur a un healthcheck, unless-stopped et des privilèges réduits ; l’outil d’administration exige les droits Docker locaux.

Plusieurs instances utilisent --instance NOM et des ports distincts. Aucun conteneur homonyme inconnu n’est remplacé. Le profil Compose est une référence facultative pour les administrateurs ; le parcours standard automatise la configuration sans commande Compose préalable.
