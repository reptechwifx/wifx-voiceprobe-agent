# Qualification Agent 0.9-021

Le protocole RFC 4733 v2 n’émet que les chiffres `0` à `9` : préambule `70483` (trois essais maximum), réponse `83047`, identifiant numérique de 14 chiffres et confirmation liée à l’appel. Les deux observations passent par les canaux Controller authentifiés. Un accusé fixe seul ne confirme aucune identité.

Deux Agents PJSUA2 2.16 ont été testés via Asterisk B2BUA LAB avec SIP Call-ID différents : confirmation bilatérale en 5,56 s, deux rapports RTP indépendants (1000 et 999 paquets), zéro perte audio après identification et ratio tonal 1 kHz de 0,9997. La perte du premier accusé est récupérée au troisième essai en 8,34 s. Une destination sans réponse reçoit seulement le préambule, jamais l’identifiant complet. 304 duplications de paquets telephone-event n’ont créé aucune trame invalide. Les tests Agent v1/v2, Controller, PostgreSQL 17 et Chromium ciblés sont passés.

Les archives PJSIP/PJSUA2 2.16 Debian 12 AMD64 et Ubuntu 24.04 AMD64 ont les mêmes SHA-256 que dans la distribution 0.9-020 ; l’image Docker AMD64 est bâtie sur les mêmes couches runtime. Synology Intel/AMD64 utilise le profil Docker. Windows reste LAB uniquement, ARM64 et PSTN physique ne sont pas qualifiés. Les chiffres numériques peuvent déclencher des commandes sur certains IVR. Aucune intervention en production n’a été effectuée par Codex.
