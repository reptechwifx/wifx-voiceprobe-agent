# Ubuntu 24.04 AMD64

```sh
curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh
```

Python3.12/ABIcp312 et glibc2.39. Ubuntu22.04 est refusé faute de qualification.

Droits sudo ou session root autorisée (omettre sudo dans ce dernier cas), terminal SSH et accès HTTPS requis. La distribution est sélectionnée et vérifiée automatiquement ; aucune compilation sur la cible. Conserver l’URL locale et les identifiants affichés après le succès vérifié, puis adopter l’Agent dans le Controller.

Mise à jour : `sudo voiceprobe-agent update`. Identité, adoption, comptes SIP, identifiants et historique sont conservés. Service systemd actif au boot.

[Résultats et limites](qualification-1.0.0.md) · [Signatures](signatures.md) · [Diagnostic](diagnostic.md).
