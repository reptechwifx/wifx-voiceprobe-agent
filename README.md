# WIFX Voice Probe Agent

| SYSTÈME | INSTALLATION | MISE À JOUR |
|---|---|---|
| Ubuntu 24.04 AMD64 | `curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh \| sudo sh` | `sudo voiceprobe-agent update` |
| Debian 12 AMD64 | `curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh \| sudo sh` | `sudo voiceprobe-agent update` |
| Docker Linux AMD64 | `curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh \| sudo sh -s -- --backend docker` | `sudo voiceprobe-agent-docker update` |
| Synology Intel AMD64¹ | `curl -fsS https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/install.sh \| sudo sh -s -- --backend docker` | `sudo voiceprobe-agent-docker update` |

**Windows portable x64 — 0.5.0-LAB, QUALIFIÉ EN LAB — NON SIGNÉ AUTHENTICODE.** Les sources et outils de construction sont disponibles ; aucun EXE Windows destiné aux clients n’est publié. Le paquet privé prépare un EXE unique avec provisioning signé, interface de statut en lecture seule, réduction dans la zone de notification et identité Windows CNG liée à l’instance, réutilisable entre interventions explicitement approuvées par WIFX. Le nettoyage explicite utilise le même EXE avec `--forget-identity`, après confirmation **Non par défaut**. Les binaires locaux restent LAB, non signés Authenticode ; la signature de production et la qualification complète sont distinctes. Voir le [guide Windows portable](docs/windows-portable.md) et la [construction Windows](docs/windows-construction.md). Les commandes et la Release Linux ci-dessus restent inchangées.

Une commande, puis adoptez l’Agent dans votre Controller. **Agent Bêta 0.9-017 · installateurs 1.0.2 · PJSIP/PJSUA2 2.16 corrigé et précompilé.**

¹ Synology : profil logiciel BusyBox/Container Manager vérifié en laboratoire ; aucun NAS physique n’a été testé. L’architecture est Intel x86-64, jamais ARM. Les commandes ci-dessus sont interactives ; SSH avec terminal et droits sudo est requis. En session root autorisée, omettre `sudo`.

[Qualification 0.9-017 et limites](docs/qualification-0.9-017.md) : correctif de gigue PJSIP vérifié sur Debian, Ubuntu et Docker ; profil Synology logiciel uniquement ; aucun nouvel EXE Windows client.

## Avant de commencer

Ubuntu24.04/Python3.12 ou Debian12/Python3.11 AMD64, ou hôte Linux AMD64 avec Docker actif. DSM nécessite Docker/Container Manager, curl et OpenSSL accessibles ; le script recherche Docker dans les chemins des paquets DSM. Docker Compose et Python sur l’hôte Docker/DSM ne sont pas requis. Prévoir de l’espace pour la livraison, les données et les sauvegardes, et l’accès HTTPS à GitHub, ses CDN et au Controller. L’installation native utilise aussi les dépôts binaires officiels du système. Aucun compte GitHub/GitLab, token Registry, clone Git ou SCP n’est nécessaire.

Le Controller proposé est `https://vp.wifx.net`. Pour un autre Controller, renseigner son adresse HTTPS avec l’option `--controller` ; ne jamais désactiver TLS. L’identité est générée localement. L’Agent apparaît en attente d’adoption ; aucun token d’enrôlement à recopier. Le dépôt distribue uniquement l’Agent, sans Controller ni PostgreSQL.

## Installation et adoption

Exécuter la ligne de votre système dans un terminal SSH. Le programme détecte OS, Python/ABI et architecture, vérifie les manifestes signés et les SHA-256, installe les binaires compatibles et vérifie le service et le Controller. **Aucune compilation PJSIP/SWIG/bindings sur la cible.** Une plateforme inconnue est refusée ; aucun fallback source automatique.

Après une nouvelle installation vérifiée, le terminal affiche directement l’URL locale réellement détectée, `admin` et le mot de passe généré. Le mot de passe n’est ni journalisé ni envoyé au Controller ; il n’est pas réaffiché pendant les mises à jour. Conservez-le dans un gestionnaire sécurisé. Ouvrez ensuite le Controller et adoptez la nouvelle identité, puis affectez les comptes SIP. WSS et les enregistrements SIP sont contrôlés après adoption.

Un succès exige le bilan `Installation terminée`, l’état ACTIF et `VOICEPROBE_AGENT_RESULT=VERIFIED_SUCCESS`. **Le code zéro du lanceur protecteur ne prouve pas un succès.** Une erreur affiche CONTROLLED_FAILURE ; ne pas ajouter un message « Exécution terminée » fondé seulement sur ce code. Le shell SSH/PuTTY reste protégé.

## SIP, audio et réseau

Controller0.9-007 requis pour les nouvelles fonctions ; mettre à jour le Controller avant les Agents. Les comptes en mode « Appels sortants et entrants » répondent après environ une seconde, sans scénario préparé ni en-tête Voice Probe obligatoire. Tonalité1kHz par défaut, écho disponible. La corrélation reste facultative ; les appels inconnus ont leur propre rapport. Le compte possède une seule autorisation de destination : appels publics OUI/NON. Les destinations internes des scénarios sont utilisables sans whitelist manuelle. Les limites de durée/capacité, les organisations et les baux Windows restent appliqués.


SIP UDP/TCP, G.722, PCMA et PCMU, télémétrie HTTPS/WSS, appels mono-sonde, écho et mesures RTP. Le réseau host Docker est le profil qualifié : un mapping de ports ne constitue pas une preuve RTP. L’interface locale écoute par défaut sur une IPv4 privée détectée, port18441/TCP. Aucun pare-feu global n’est modifié ; l’installation refuse les conflits de ports et ne stoppe aucune autre application. Les règles réseau locales et le NAT doivent permettre vos flux SIP/RTP.

Les données, identités et credentials sont séparés des binaires : `/opt/voiceprobe`, `/var/lib/voiceprobe` en natif ; dossier dédié persistant en Docker, volume `/volumeN/docker/voiceprobe-agent` détecté sur DSM. Ne supprimez jamais ces données pour mettre à jour. Plusieurs instances Docker utilisent `--instance`, des ports et des dossiers distincts ; ne jamais écraser une instance existante.

## Mise à jour et exploitation

```sh
sudo voiceprobe-agent status
sudo voiceprobe-agent update --check
sudo voiceprobe-agent update
sudo voiceprobe-agent diagnose
sudo voiceprobe-agent rollback
sudo voiceprobe-agent reset-password
```

Docker/DSM : remplacer `voiceprobe-agent` par `voiceprobe-agent-docker`, ajouter `--instance NOM` pour une instance autre que default. En cohabitation natif/Docker, utiliser `voiceprobe-agent-native` pour cibler explicitement le natif. Une mise à jour préserve identité, adoption, comptes SIP, credentials, paramètres, ports et historique ; une sauvegarde privée est vérifiée avant bascule. Le premier déploiement n’a pas encore de version précédente à restaurer : son rollback est refusé. Aucun update planifié n’est activé par défaut.

Les appels sont pris en compte par le gestionnaire : drainage qualifié sur l’Agent actuel, refus/report si la sécurité n’est pas établie. La version historique003 n’offre pas le même protocole de drainage ; une sonde occupée doit être laissée en service jusqu’à une fenêtre sûre. Ne pas promettre une coordination des campagnes Controller non implémentée.

Pour automatiser, utiliser le résultat strict dans une condition, sans quitter le shell parent :

```sh
if sudo voiceprobe-agent update --strict; then printf 'Mise à jour vérifiée.\n'; else printf 'ÉCHEC CONTRÔLÉ.\n' >&2; fi
```

Une interruption se reprend avec la même commande. Une perte du mot de passe nécessite `reset-password`, jamais une réinstallation ou une nouvelle adoption. Le mode non interactif utilise un fichier de mot de passe privé avec `--password-file`, jamais un secret obligatoire dans les arguments.

## Téléchargements, signatures et licences

[Release officielle](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/tag/agent-0.9-009-installer-1.0.2) · [SHA-256](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-009-installer-1.0.2/SHA256SUMS) · [Qualification](docs/qualification-0.9-009.md) · [Signatures](docs/signatures.md) · [Licences](docs/licences.md).

Les manifestes sont signés RSA4096/SHA256 avec une racine de production épinglée dans le bootstrap. Empreinte SPKI SHA-256 : `f65020bb2c6139ba381094533afa0a28fbf3b34f7d6203f2a140b9ce999fde55`. TLS protège le premier téléchargement officiel ; les signatures authentifient ensuite les catalogues et empreintes. Les séquences et expirations sont vérifiées. Les images sont des archives publiques importées automatiquement et vérifiées par identité immuable ; aucun GHCR/Registry privé client n’est requis.

Sources originales Agent et outillage : [GPL-3.0-or-later](LICENSE). Les composants tiers conservent leurs licences, notamment PJSIP GPL-2.0-or-later avec ses exceptions. Notices et sources correspondantes exactes PJSIP/Python/NumPy/OpenBLAS/Debian accompagnent la Release. Les seules clés tierces distribuées sont des exemples et constantes d’autotest déjà publics, inventoriés et autorisés ; aucune identité existante, clé de signature privée ou secret WIFX n’est inclus. Le code et l’historique privés du Controller sont exclus.

## Diagnostic, arrêt et limites

[Ubuntu](docs/installation-ubuntu.md) · [Debian](docs/installation-debian.md) · [Docker](docs/installation-docker.md) · [Synology](docs/installation-synology.md) · [Mise à jour](docs/mise-a-jour.md) · [Diagnostic et arrêt](docs/diagnostic.md) · [Sécurité](SECURITY.md) · [Construction](docs/developpement.md).

Pour retirer l’Agent du service sans détruire ses données, terminer les appels puis désactiver/arrêter uniquement son service systemd ou son conteneur, selon le guide de diagnostic. L’effacement des identités/volumes n’est pas une opération de mise à jour.

Plateformes non qualifiées : Ubuntu22.04, autres Debian, ARM64, NAS Synology physique et réseau IPv6 réel. SIP TLS n’est pas annoncé qualifié par les essais UDP/TCP. Temps observés en LAB : Ubuntu286s, Debian182s, Docker avec daemon vierge35s ; ils dépendent du réseau, des dépôts système et du matériel. Aucun test n’a utilisé un Controller WIFX, une sonde ou un NAS de production.


### Stabilité et mises à jour008

La version008 corrige un chemin de crash natif à la réponse entrante et conserve les rapports après redémarrage sans bloquer la communication. Il distingue les causes de refus SIP et acquitte les configurations effectivement appliquées. Le SDK PJSIP2.16 précompilé est réutilisé. Les commandes ci-dessus utilisent les fichiers publics de la Release008, vérifiés depuis des VM Ubuntu, Debian et Docker sans authentification.

La maintenance distante008 réutilise exclusivement l’updater officiel. Elle exige une activation locale explicite du relais privilégié sur chaque installation gérée ; les anciens Agents ne l’acquièrent pas par une commande du Controller. Linux : `sudo voiceprobe-agent enable-remote-update`. Docker : `sudo voiceprobe-agent-docker enable-remote-update` (avec l’instance appropriée). Aucun shell distant, aucun démarrage d’un Agent hors ligne ni mise à jour automatique non demandée. Windows conserve le parcours nouvel EXE personnalisé et l’identité CNG.

### Capacité centrale009 et mesures Windows

Avec Controller009, la capacité simultanée se règle uniquement sur la fiche Agent (1–128, plafond compilé du moteur ; dix appels réels qualifiés). Les anciens plafonds locaux et par compte ne limitent plus les Agents compatibles ; aucune limitation automatique par chargeCPU. Une configuration qui modifie les comptes attend la fin des appels en cours avant application. Les anciennes sondes conservent leur comportement jusqu’à mise à jour officielle.

Windows0.5.0-LAB affiche les mesures RTP réellement disponibles pendant les appels, puis les moyennes numériques de la session, sans jugement de qualité destiné au client. Pertes : somme des paquets perdus / somme des paquets attendus. Jitter : moyenne pondérée par les paquets reçus. Audio : moyenne des puissances linéaires pondérée par la durée analysée, reconvertie en dBFS. Interruptions : moyenne des durées cumulées des tests disposant de la mesure. L’audio est analysé en fin d’appel : les valeurs temps réel correspondantes restent indisponibles. Le provisioning signé, CNG, TLS et l’absence d’administration locale sont conservés. Aucun certificat Authenticode ni nouveau SDK n’est requis pour les testsLAB.
