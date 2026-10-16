# Qualification Agent0.9-008 — gestionnaire1.0.2

Release : [agent-0.9-008-installer-1.0.2](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/tag/agent-0.9-008-installer-1.0.2). Sources effectivement construites : `abcfe69d03514d405d90c1459fe86fbcce28d1d1`, dans l’historique public Agent uniquement. Les commits de documentation et de canal ultérieurs ne modifient pas les artefacts immuables.

| Plateforme | Résultat réel |
|---|---|
| Ubuntu24.04 AMD64 / Python3.12 | Mise à jour par le canal GitHub public, signatures/TLS, build réellement installé, identité/adoption/admin/ports et2comptesUDP/TCP conservés |
| Debian12 AMD64 / Python3.11 | Mêmes contrôles, avec SDK correspondant à l’ABIcp311 |
| Docker LinuxAMD64 | Installation008 du candidat via bootstrap, mise à jour finale depuis GitHub dans un moteur indépendant ; identité, volume et2comptes conservés |
| SynologyIntel | MécanismeDockerAMD64 représentatif ; pas de nouvelle qualification matérielleDSM |
| Windows11 x64 | EXE0.4.0-LAB réellement exécuté, Python3.13.16/PJSIP2.16 ; aucun EXE client officiel dans cette Release |

## Stabilité et rapports

Le SDK2.16 reste inchangé. L’assertion à la libération des données SIP clonées a été reproduite avec une réponse finale synchrone dans le callback entrant. Le correctif diffère la réponse après retour du callback ;30INVITE réels TCP/UDP×403/405/486 passent sous Linux et Windows sans abort. Quatre appels entrants/sortants par sonde ont réellement échangé leur RTP ; l’appel supplémentaire a reçu486 sans redémarrage. Cette preuve LAB ne permet pas d’attribuer définitivement le crash d’une machine de production non examinée.

Le refus422 reproduit concerne le compte absent d’un rapport entrant de reprise après crash. Le Controller008 accepte le cas de reprise incomplet sans inventer Call-ID, codec ou RTP. Onze rapports entrants et cinq rapports de scénario soumis deux fois ont produit seize résultats uniques. L’outbox conserve les rejets permanents sans bloquer tous les autres échanges. Avec un ancien Controller, les rapports inconnus restent récupérables en attente de compatibilité.

## Mise à jour centralisée

Les trois plateformes ont été commandées par de vrais clics GUI vers une cible de version synthétique réservée au LAB, puis revenues à008 par rollback officiel. Cette cible n’est pas une Release publiée. Le succès nécessitait le résultat de l’updater et une nouvelle version effectivement observée après reconnexion HTTPS/WSS. Une archive réellement corrompue a été refusée avant arrêt ; un relais root interrompu pendant un appel réel a repris la même requête sans couper cet appel.

Les Agents004/007 exigent une première mise à jour locale puis l’activation explicite du relais. Linux : `sudo voiceprobe-agent enable-remote-update`. Docker : `sudo voiceprobe-agent-docker enable-remote-update` (préciser l’instance si nécessaire). Aucun shell distant ni credential root dans le Controller. Un Agent hors ligne ne peut pas être démarré par cette fonction. Windows conserve la génération d’un nouvel EXE et son identitéCNG.

## Mesures observées

Temps de mise à jour finale depuis GitHub, téléchargements et vérifications compris, dans les VM LAB :

- Ubuntu24.04 : 17.17secondes.
- Debian12 : 13.95secondes.
- Docker indépendant : 20.0secondes.

Ces mesures concernent une mise à jour avec dépendances déjà présentes ; elles ne constituent pas une durée garantie d’installation neuve. Aucune compilation PJSIP sur les cibles.

## Sources, signatures et sécurité

SHA256 des distributions : [inventaire signé indirectement par les manifestes](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-008-installer-1.0.2/SHA256SUMS). RacineRSA4096 conservée, SPKISHA256 `f65020bb2c6139ba381094533afa0a28fbf3b34f7d6203f2a140b9ce999fde55`. Les signatures sont contrôlées par l’updater avant installation. Les sources tierces des SDK inchangés sont réutilisées depuis l’asset public immuable004 référencé dans le manifeste signé, sans duplication ni modification d’une ancienne Release.

Audit des fichiers, archives, roues et dix couches Docker : aucune valeur confidentielle connue, aucun code Controller ni identité existante. Les seules clés de test incorporées sont les six constantes publiques GnuTLS déjà autorisées et vérifiées contre les sources amont ; aucune nouvelle exception publique.191tests Agent :177réussis,14ignorés dans l’environnement unitaire ; les essais natifs et Windows ci-dessus ont été exécutés séparément avec les véritables SDK. Les sources exportées publiques ont passé la même suite.

Aucun déploiement réel, compte SIP réel, appel facturé, workflow ou build distant. Les versions Linux antérieures et leurs artefacts restent immuables. Les limites locales de capacité restent respectées ; leur augmentation centralisée n’est pas revendiquée.
