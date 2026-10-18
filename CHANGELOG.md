## Agent Bêta 0.9-019 — installateurs 1.0.2

Identification bidirectionnelle des Agents compatibles par RTP telephone-event pendant les dix premières secondes de l'appel. Les observations DTMF sont confirmées par le Controller et permettent d'associer deux rapports RTP malgré des Call-ID SIP distincts. Les mesures audio de référence utilisent la phase après identification ; les compteurs bruts restent consultables. Le runtime PJSIP/PJSUA2 corrigé de 0.9-017 et le gestionnaire de mise à jour officiel sont conservés. Les Agents 0.9-017 restent compatibles avec le Controller 0.9-019 pendant la montée de version. Aucun EXE Windows client n'est publié. Voir [la qualification 0.9-019](docs/qualification-0.9-019.md).


## Agent Bêta 0.9-017 — installateurs 1.0.2

Correction arithmétique exacte du calcul de jitter dans PJSIP 2.16, vérifiée après longue durée de fonctionnement, sur PCMA, PCMU et G.722. Runtimes natifs Debian 12/Ubuntu 24.04 AMD64 et image Docker AMD64 reconstruits. Distribution et mises à jour par le gestionnaire officiel, avec manifestes signés et sources correspondantes. Compatibilité Synology Intel/AMD64 via Docker qualifiée sur profil logiciel, sans essai sur NAS physique. Windows reste réservé au LAB, sans EXE client Authenticode. Voir [la qualification 0.9-017](docs/qualification-0.9-017.md).

# Historique

## Windows portable 0.2.0-LAB — en cours de qualification

EXE personnalisé unique avec provisioning v2 signé, lié au template autorisé et à son nonce. Identité persistante CNG par utilisateur et instance, réutilisable entre interventions explicitement approuvées, secrets temporaires protégés en mémoire, interface informative en français avec ressources officielles WIFX, zone de notification et confirmation de fermeture pendant un appel. Suppression explicite de la seule identité de cette sonde avec `--forget-identity`, confirmation Non par défaut et refus si elle est utilisée. Worker de packaging isolé avec catalogue fermé ; production refusée tant que la signature Windows de confiance n’est pas qualifiée. Les sources de l’administration Controller restent privées. Aucun EXE client ni nouvelle Release Windows n’est publié ; les artefacts, signatures, commandes et canaux Linux/Docker 1.0.0 sont conservés.

## Windows portable 0.1.0-LAB — en cours de qualification

Sources et construction Windows x64, PJSIP/PJSUA2 2.16, Python 3.13.16 et interface native de statut en lecture seule. Identité éphémère et SIP synthétique sans périphérique audio. Les exécutables locaux sont LAB non signés Authenticode ; aucune Release Windows destinée aux clients n’est publiée. Les distributions Linux/Docker 1.0.0 restent inchangées. Voir le guide Windows.

## Agent Bêta0.9-004 — installateurs1.0.0

Première Release officielle publique signée ; PJSIP/PJSUA2 2.16 précompilé Ubuntu24.04/cp312, Debian12/cp311 et Docker AMD64. Canaux HTTPS GitHub signés et assets publics, sans accès privé client. Qualification réelle des installations, adoption, SIP/RTP/écho, préservation, rollback et reprise ; voir le rapport. Profil Synology logiciel uniquement, sans NAS physique. Aucun changement des moteurs SIP/RTP ou du Controller dans cette publication.

## Agent 0.9-012

Observations RTP/PJSIP réelles par réception : histogramme PDV relatif, pertes de lecture/distribution, intervalles de 2 s et capacité explicite. Aucun délai réseau inventé ni profil PLC WSOLA assimilé à Appendix I. MOS G.722 et G.711 avec pertes WSOLA restent indéterminés. Mise à jour Linux/Docker indépendante du Controller et sans réinstallation ; les EXE Windows existants restent indépendants.
