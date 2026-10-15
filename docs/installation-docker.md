# Docker Linux AMD64

```sh
curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh -s -- --backend docker
```

Docker actif, curl et OpenSSL ; aucun Registry privé ni Compose requis. Image Agent seule importée depuis GitHub et vérifiée par identités immuables. Réseau host, données persistantes dédiées et restart unless-stopped.

Droits sudo ou session root autorisée (omettre sudo dans ce dernier cas), terminal SSH et accès HTTPS requis. La distribution est sélectionnée et vérifiée automatiquement ; aucune compilation sur la cible. Conserver l’URL locale et les identifiants affichés après le succès vérifié, puis adopter l’Agent dans le Controller.

Mise à jour : `sudo voiceprobe-agent-docker update`. Pour plusieurs instances : dossiers et ports distincts, puis `--instance NOM`. Le conteneur reste gérable depuis Container Manager.

[Résultats et limites](qualification-1.0.1.md) · [Signatures](signatures.md) · [Diagnostic](diagnostic.md).
