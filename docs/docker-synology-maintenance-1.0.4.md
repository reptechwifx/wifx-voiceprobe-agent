# Maintenance Docker/Synology 1.0.4 — Agent 0.9-026

Gestionnaire signé **2026102010**, Agent et images **0.9-026 inchangés**.
Cette maintenance remplace le gestionnaire 1.0.3/2026102009, sans réécrire les
anciennes releases. Elle ne déploie rien automatiquement sur un NAS.

## Correctif ciblé

Le gestionnaire 1.0.3 contrôlait `network-code/bin` avant son `chmod` ; un dossier
root en 777, notamment après héritage ACL, était refusé : « Code diagnostic non
sûr. ». La transaction revenait correctement à 025.

Le nouveau gestionnaire normalise les chemins dédiés dans cet ordre :

1. `management/network-code` : root:root, 0755.
2. `management/network-code/bin` : root:root, 0755.
3. Le seul programme signé `bin/traceroute` : fichier root:root, 0755.
4. `management/network-socket` : root:1000, 0750.

Les ACL POSIX d'accès et par défaut sont retirées **sur ces seuls objets**.
Le `chmod` DSM doit convertir les ACL Windows en permissions UNIX. Après chaque
opération : vérification du même inode, du propriétaire, du groupe, du mode et
des attributs ACL, y compris les attributs virtuels Synology interrogés directement.
Une ACL résiduelle, inconnue ou illisible interdit le succès. Aucune commande ACL
Synology hôte, aucun parcours récursif et aucune modification des ACL du partage.
Le programme provient du gestionnaire signé et est remplacé atomiquement si son
contenu diffère ; liens symboliques et fichiers liés ailleurs sont refusés.

Le parent `management` est **seulement audité**, jamais normalisé. Ses ACL par
défaut POSIX sont conservées ; ses ACL d'accès doivent pouvoir être certifiées
absentes ou vides. Une ACL d'accès non vide est refusée par prudence, même si elle
pourrait être restrictive. Dans ce cas, conserver l'erreur précise et faire
examiner uniquement ce parent par l'administrateur : ne pas désactiver le contrôle
ni modifier les ACL globales. La sécurité d'un parent inconnu n'est pas déduite
du seul mode 755/555.

## Protections conservées

Agent UID/GID 1000, aucune capacité, rootfs en lecture seule, `cap_drop ALL`,
`no-new-privileges`. Auxiliaire par instance UID0:GID1000, uniquement NET_RAW,
rootfs en lecture seule et `no-new-privileges`, sans Docker.sock ni données SIP.
Le protocole auxiliaire, traceroute, SIP/RTP/DTMF et les images restent inchangés.
Les droits et les sondes UDP/ICMP réelles restent requis avant VERIFIED_SUCCESS.
Une absence de réponse d'un routeur n'est pas assimilée à une perte RTP.

## Procédure opérateur

Après lecture du rapport LAB et contrôle des signatures officielles :

1. Controller → Agents → **NAS-Studio2829 → Mettre à jour**.
2. Attendre **Succès distant vérifié**, Agent réellement **0.9-026** connecté et
   gestionnaire **2026102010**. Vérifier les diagnostics UDP puis ICMP applicables.
3. Vérifier la conservation de l'identité, des comptes SIP et de la configuration.
4. Après validation du premier NAS, répéter sur **NAS Air-Club (server01)**.

Aucune commande SSH de correction des permissions n'est requise pour un profil
certifiable. Le gestionnaire signé est chargé avant la préparation des dépendances.
En cas de refus : ne pas enchaîner les tentatives ; conserver le motif et
`update-state.json`, puis contrôler que le rollback a restauré 025.
Ne pas annoncer un succès si la transaction est `rolled_back`.

**Limite :** le LAB reproduit un héritage ACL POSIX réel et les modes observés,
avec simulations ciblées des attributs Synology. Ce n'est pas une qualification
sur DSM physique ni sur ses noyaux 3.10/4.4. La validation finale des deux NAS
appartient à l'opérateur ; Codex n'y accède pas.
