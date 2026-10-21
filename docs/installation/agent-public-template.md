# WIFX Voice Probe Agent

Distribution Agent uniquement, sans Controller, PostgreSQL ni credentials WIFX.

Bêta 0.9-027, installateur 1.0.4. Binaires PJSUA2 2.16 avec observateur RTP temporel : Ubuntu 24.04 AMD64/Python 3.12, Debian 12 AMD64/Python 3.11 et Debian 13 ARM64/Python 3.13. Installation native avec systemd et GUI locale sur le port 18441. Docker Linux AMD64 uniquement ; Docker ARM64 hors périmètre. La qualification LAB ARM64 reste distincte de la validation sur Raspberry Pi physique.

La distribution officielle Agent est publiée dans https://github.com/reptechwifx/wifx-voiceprobe-agent ; consulter son README et son rapport de qualification pour les plateformes et commandes effectivement disponibles. Les releases comprennent manifestes signés, SHA-256, dépendances binaires et une image Docker Agent seule. Aucun compte GitLab ou token Registry client n’est requis pour la distribution HTTPS.

Installation native : `curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh -s -- install --strict`. Activation de la maintenance distante : `sudo voiceprobe-agent enable-remote-update --strict`. Les mises à jour normales sont ensuite demandées dans le Controller, Agents → Mettre à jour.

Après installation : `sudo voiceprobe-agent status`, `sudo voiceprobe-agent update`, `sudo voiceprobe-agent rollback`, `sudo voiceprobe-agent diagnose`. La première installation affiche directement les identifiants sur le terminal ; les mises à jour préservent l’identité et les comptes SIP.

Le code retour protecteur par défaut ne suffit pas à conclure à un succès. Automatisation : `if sudo voiceprobe-agent update --strict; then printf 'Mise à jour vérifiée.\n'; else printf 'Échec contrôlé.\n' >&2; fi`.

Construction locale : `scripts/build-agent-binaries.py`, `scripts/prepare-agent-public-runtime.py`, puis `scripts/package-agent-release.py`. Compilation exclusivement sur Marc-Home, jamais sur une cible normale. Les clés privées de signature et les configurations installées ne font pas partie de cet export.
