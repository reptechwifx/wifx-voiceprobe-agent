# WIFX Voice Probe Agent

Distribution Agent uniquement, sans Controller, PostgreSQL ni credentials WIFX.

Installateur 1.0.0 pour Agent 0.9-004. Binaires PJSUA2 2.16 : Ubuntu 24.04 AMD64/Python 3.12 et Debian 12 AMD64/Python 3.11. Docker Linux AMD64 ; profil Synology Intel préparé, matériel à qualifier. ARM64 et Ubuntu 22.04 non qualifiés.

L’URL publique officielle reste à provisionner. Aucun endpoint illustratif n’est une installation disponible. Les releases comprennent manifestes signés, SHA-256, dépendances binaires et une image Docker Agent seule. Aucun compte GitLab ou token Registry client n’est requis pour la distribution HTTPS.

Après installation : `sudo voiceprobe-agent status`, `sudo voiceprobe-agent update`, `sudo voiceprobe-agent rollback`, `sudo voiceprobe-agent diagnose`. La première installation affiche directement les identifiants sur le terminal ; les mises à jour préservent l’identité et les comptes SIP.

Le code retour protecteur par défaut ne suffit pas à conclure à un succès. Automatisation : `if sudo voiceprobe-agent update --strict; then printf 'Mise à jour vérifiée.\n'; else printf 'Échec contrôlé.\n' >&2; fi`.

Construction locale : `scripts/build-agent-binaries.py`, puis `scripts/package-agent-release.py`. Compilation exclusivement sur Marc-Home, jamais sur une cible normale. Les clés privées de signature et les configurations installées ne font pas partie de cet export.
