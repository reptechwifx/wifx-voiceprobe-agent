# Historique

## Windows portable 0.2.0-LAB — en cours de qualification

EXE personnalisé unique avec provisioning v2 signé, lié au template autorisé et à son nonce. Identité persistante CNG par utilisateur et instance, réutilisable entre interventions explicitement approuvées, secrets temporaires protégés en mémoire, interface informative en français avec ressources officielles WIFX, zone de notification et confirmation de fermeture pendant un appel. Suppression explicite de la seule identité de cette sonde avec `--forget-identity`, confirmation Non par défaut et refus si elle est utilisée. Worker de packaging isolé avec catalogue fermé ; production refusée tant que la signature Windows de confiance n’est pas qualifiée. Les sources de l’administration Controller restent privées. Aucun EXE client ni nouvelle Release Windows n’est publié ; les artefacts, signatures, commandes et canaux Linux/Docker 1.0.0 sont conservés.

## Windows portable 0.1.0-LAB — en cours de qualification

Sources et construction Windows x64, PJSIP/PJSUA2 2.16, Python 3.13.16 et interface native de statut en lecture seule. Identité éphémère et SIP synthétique sans périphérique audio. Les exécutables locaux sont LAB non signés Authenticode ; aucune Release Windows destinée aux clients n’est publiée. Les distributions Linux/Docker 1.0.0 restent inchangées. Voir le guide Windows.

## Agent Bêta0.9-004 — installateurs1.0.0

Première Release officielle publique signée ; PJSIP/PJSUA2 2.16 précompilé Ubuntu24.04/cp312, Debian12/cp311 et Docker AMD64. Canaux HTTPS GitHub signés et assets publics, sans accès privé client. Qualification réelle des installations, adoption, SIP/RTP/écho, préservation, rollback et reprise ; voir le rapport. Profil Synology logiciel uniquement, sans NAS physique. Aucun changement des moteurs SIP/RTP ou du Controller dans cette publication.
