# Agent 0.9-026 — Raspberry Pi 4 / Debian 13 ARM64

Distribution native avec systemd. Même Agent, GUI et gestionnaire signés que les autres installations Linux. Debian 13, userspace ARM64 et Python 3.13 sont requis ; armhf et Docker ARM64 sont exclus. Aucun build n’est effectué sur le Raspberry.

La qualification ARM64 en LAB et la validation sur un Raspberry physique sont distinctes. Aucun Raspberry réel n’a été utilisé par Codex. Consulter le rapport de livraison 026 pour les résultats effectivement acquis. La version déployée du Controller doit être vérifiée par l’opérateur ; la publication de 025 ne prouve pas son déploiement.

## Installation — première commande

Dans un terminal de l’administrateur du Raspberry, avec curl et les droits sudo habituels :

```sh
curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh | sudo sh -s -- install --strict
```

L’installateur contrôle CPU, userspace, Python et systemd, vérifie les signatures et SHA-256, installe les dépendances Debian autorisées et les runtimes binaires, puis démarre le service. Il remet les accès initiaux dans le terminal. Une installation vérifiée affiche `VOICEPROBE_AGENT_RESULT=VERIFIED_SUCCESS`.

Ouvrir **http://IP_DU_RASPBERRY:18441**, s’authentifier puis suivre le parcours Linux existant pour le Controller et l’adoption. La GUI est installée et démarrée avec l’Agent. Les comptes SIP se configurent depuis le Controller. Conserver les accès initiaux dans un gestionnaire de mots de passe.

Le moteur utilise le périphérique audio synthétique existant ; aucune carte son physique n’est requise. Le service tourne avec l’utilisateur système `voiceprobe`. La capacité réseau nécessaire appartient au binaire traceroute dédié ; le moteur Agent reste sans capacité effective.

## Maintenance distante — deuxième commande

```sh
sudo voiceprobe-agent enable-remote-update --strict
```

Cette activation autorise le relais privilégié existant ; elle ne constitue pas une mise à jour. Ensuite : **Voice Probe → Agents → Mettre à jour**. Le gestionnaire officiel signé est chargé avant les dépendances ; le succès exige la vérification de la version chargée et sa remontée au Controller. Aucun SSH n’est nécessaire pour ces mises à jour normales.

Les identités, secrets, comptes SIP, paramètres locaux et historiques persistent. Le gestionnaire conserve les sauvegardes et le mécanisme de retour arrière existants. Une version identique ne doit pas provoquer de réinstallation.

## Validation physique par l’opérateur

À effectuer après autorisation, sur le Raspberry réel. Les résultats LAB ne remplissent pas cette grille.

| Contrôle | Preuve attendue |
| --- | --- |
| Première commande | Installation vérifiée, aucun compilateur demandé |
| GUI 18441 et authentification | Accès depuis le LAN autorisé, version chargée 026 |
| Adoption | Identité présente dans le Controller, HTTPS/WSS connectés |
| Comptes SIP | REGISTER confirmé, plusieurs comptes conservés |
| Deux directions | Raspberry → Linux et Linux → Raspberry établis |
| Identification | DTMF v2 confirmé, deux rapports indépendants, couverture 2/2 |
| Mesures | Tonalité 1 kHz, RTP, MOS-LQ et jitter disponibles selon leur qualification |
| Réseau | UDP automatique vers le RTP observé ; ICMP complémentaire sur dégradation |
| QoS | Capture réelle RTP/RTCP DSCP46 et SIP DSCP40 ; une valeur configurée ne suffit pas |
| Ressources | CPU, mémoire, stockage et température seulement si le noyau l’expose |
| Reboot | systemd redémarre l’Agent, reconnexion et configuration conservées |
| Deuxième commande | Maintenance distante activée |
| Mise à jour ultérieure | Demandée depuis le Controller, succès effectif et données conservées |

La qualification de performance, température, interface réseau physique et marquage sur le réseau du site reste à réaliser sur le matériel réel. Aucun accès à ce matériel ni déploiement de production n’est effectué par Codex dans ce chantier.
