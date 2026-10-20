# Maintenance Docker / Synology 1.0.3

Livraison ciblée du gestionnaire signé 2026102009, conservant l'Agent 0.9-026
et toutes ses images et distributions. Aucun déploiement par Codex.

## Mise à jour des deux NAS existants

Après examen des preuves LAB et publication du catalogue signé :

1. Dans Voice Probe → Agents, vérifier que NAS-Studio2829 est connecté en 025
   et que la maintenance distante est activée. Vérifier le catalogue 026.
2. Cliquer **Mettre à jour**. Le gestionnaire 008 vérifie la signature du 009
   et le charge avant préparation de l'Agent. La transition recrée le seul Agent
   concerné et son auxiliaire de diagnostic ; le worker de maintenance existant
   est conservé.
3. Exiger **Succès distant vérifié**, version active 026 et reconnexion HTTPS/WSS.
   Un échec impose la lecture de son motif ; il ne valide pas l'installation.
4. Effectuer un diagnostic UDP puis un ICMP et examiner les résultats remontés
   dans les rapports. Les sauts silencieux ne constituent pas des pertes RTP.
5. Après validation de cette première sonde, appliquer la même procédure à
   NAS Air-Club. Ne pas lancer les deux essais physiques simultanément.

Aucune commande SSH n'est nécessaire au fonctionnement normal. Ne pas relancer
de bootstrap 021, ne pas supprimer/recréer manuellement les données et ne pas
modifier le conteneur de maintenance. Ne pas modifier les autres stacks du NAS.

Le résultat CLI officiel reste `VOICEPROBE_AGENT_RESULT=VERIFIED_SUCCESS` ;
la GUI n'affiche le succès distant qu'après confirmation de la version chargée.
Relancer à version identique conforme ne remplace ni ne redémarre les conteneurs.

## Permissions attendues et contrôle matériel

Agent : UID/GID1000, readonly, drop ALL, CapAdd vide, NNP actif, réseau host.
L'absence de NET_RAW sur ce conteneur est maintenant intentionnelle : son proxy
utilise un socket Unix privé, monté readonly, vers le seul auxiliaire de l'instance.

Auxiliaire `voiceprobe-agent-network-default` : UID0/GID1000 **limité à NET_RAW**,
readonly, drop ALL, NNP actif, réseau host, aucun Docker.sock ni volume de données
Agent/SIP. Le gestionnaire contrôle aussi les capacités des processus traceroute.
Aucun NET_ADMIN, SETUID ou SETGID accordé. Aucun sysctl hôte ou pare-feu modifié.

Les noyaux Synology peuvent omettre `NoNewPrivs` dans `/proc`. Le contrôle utilise
`PR_GET_NO_NEW_PRIVS` et refuse un résultat inconnu. Une option Docker affichée
seule ne remplace pas cette interrogation ni les sondes réelles.

La validation physique reste réservée à l'opérateur : version Docker et noyau,
succès distant, permissions effectives, émission UDP/ICMP vers un correspondant
autorisé, résultats Controller, comptes SIP et identité conservés. Le LAB récent
et les simulations de dispositions `/proc` anciennes ne certifient pas les NAS.
Ne pas supprimer les sauvegardes de rollback avant cette validation.

## Installation neuve

La commande officielle est conservée, après publication de cette maintenance :

```sh
curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh -s -- install --strict --backend docker
```

L'activation initiale de maintenance reste la commande existante :

```sh
sudo voiceprobe-agent-docker enable-remote-update --strict
```

Ces commandes concernent une nouvelle installation ou une activation initiale,
pas la réparation répétée des deux NAS déjà administrés à distance.

## Intégrité et limites

Nouvelle release immuable : `agent-0.9-026-installer-1.0.3` dans le dépôt public
`reptechwifx/wifx-voiceprobe-agent`. Vérifier `manager.manifest` et `manager.sig`
avec la clé officielle conservée. Comparer l'empreinte du programme à
`manager_sha256` et la séquence à 2026102009. Le catalogue applicatif 026,
son bootstrap, l'image Agent et les SDK restent ceux de la release 1.0.2.

Aucune image Controller, migration PostgreSQL ou nouvelle dépendance système.
Windows, ARM64, Linux natif et moteur VoIP conservés. Docker rootless refusé.
Les qualifications physiques 3.10.108/Docker20.10.3 et 4.4.302+/Docker24.0.2
restent à effectuer par l'opérateur ; aucune tentative de production par Codex.
