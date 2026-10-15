# Synology Intel AMD64

```sh
curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh -s -- --backend docker
```

DSM avec Container Manager/Docker, curl et OpenSSL. Le bootstrap cherche Docker dans PATH et les chemins des paquets DSM ; choisit un volume /volumeN accessible. Pas de Python/systemd natif requis. Profil logiciel BusyBox/DSM qualifié ; aucun NAS physique ni IPv6 DSM réel qualifié. Aucun pare-feu global n’est modifié.

Droits sudo ou session root autorisée (omettre sudo dans ce dernier cas), terminal SSH et accès HTTPS requis. La distribution est sélectionnée et vérifiée automatiquement ; aucune compilation sur la cible. Conserver l’URL locale et les identifiants affichés après le succès vérifié, puis adopter l’Agent dans le Controller.

Mise à jour : `sudo voiceprobe-agent-docker update`. Pour plusieurs instances : dossiers et ports distincts, puis `--instance NOM`. Le conteneur reste gérable depuis Container Manager.

[Résultats et limites](qualification-1.0.0.md) · [Signatures](signatures.md) · [Diagnostic](diagnostic.md).
