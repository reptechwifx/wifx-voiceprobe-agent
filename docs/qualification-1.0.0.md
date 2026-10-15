# Qualification de la première distribution GitHub

15 octobre 2026 · Agent Bêta0.9-004 · installateurs1.0.0 · PJSIP/PJSUA2 2.16.

Release : [agent-0.9-004-installer-1.0.0](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/tag/agent-0.9-004-installer-1.0.0). Sources du build : `d9b46ac98af1e4bd8e3339a860b00bebd59ffe8e`, commit public indépendant de l’historique GitLab. Les changements documentaires ultérieurs ne reconstruisent pas cette image immuable.

## Plateformes et temps mesurés

| Cible LAB | Python / ABI | Résultat | Installation |
|---|---|---|---|
| Ubuntu24.04 AMD64, VM propre QEMU/TCG2vCPU/2Go, systemd | 3.12.3 / cp312 | Qualifiée | 285,56s |
| Debian12 AMD64, VM propre QEMU/TCG2vCPU/2Go, systemd | 3.11.2 / cp311 | Qualifiée | 181,82s |
| Linux Docker AMD64, daemon20.10.24 isolé et vierge, sans image Agent préchargée | 3.11 dans l’image | Qualifiée | 35,32s |
| Docker Desktop29.7.2, autre instance et données dédiées | 3.11 dans l’image | Qualifiée | 26,83s |
| BusyBox/ash, Docker accessible seulement par chemin Container Manager, sans Python/systemd hôte | 3.11 dans l’image | Profil DSM logiciel qualifié | 27,01s |

Les temps vont du lancement du bootstrap au bilan vérifié ; ils excluent le démarrage des VM, la préparation du PBX/CA LAB et l’adoption. Le profil DSM réutilisait l’identité d’image déjà vérifiée sur Docker Desktop ; le test de daemon Docker vierge vérifie l’import effectif sans cache. Une nouvelle installation par la forme courte curl→sh du README a aussi réussi en40,16s. Les tests ne garantissent aucune durée sur un réseau ou matériel différent.

Les installations neuves utilisent les URL publiques exactes et des options de Controller/CA/ports/instances réservées au LAB. Aucun défaut TLS n’est ignoré. Les lignes natives du README sont aussi exécutées telles quelles en réinstallation idempotente en conservant le Controller LAB existant ; aucune connexion à WIFX. La variante root du profil Docker/DSM omet sudo, comme documenté.

## Contrôles réellement réussis

- Treize assets téléchargés anonymement depuis GitHub Releases/CDN ; métadonnées raw et assets comparées, TLS actif, SHA256SUMS identique, deux signatures de production vérifiées. Les empreintes serveur GitHub concordent aussi pour les treize fichiers.
- Bon SDK par OS/Python/SOABI/glibc, dépendances dynamiques résolues, import PJSUA2 et initialisation SIP réels. Aucun gcc/g++/make/cmake/SWIG sur les cibles ; pip fonctionne hors ligne sur wheels verrouillés. Les deux runtimes Fortran/quadmath vendus par le wheel NumPy amont sont remplacés par les bibliothèques système déclarées ; provenance de la transformation conservée.
- Services systemd actifs et activés au boot, interfaces locales accessibles, mots de passe initiaux remis au terminal et vérifiés par hash puis véritable connexion HTTP admin. Absence du mot de passe dans journaux et fichiers de remise en clair. Les mises à jour ne le réaffichent pas.
- Identités uniques, adoption via Controller LAB, HTTPS/WSS après adoption, deux REGISTER200 par Agent avec comptes UDP/TCP de laboratoire. Aucune adoption ou identité régénérée pendant les mises à jour.
- 18 appels d’écho réels complétés, qualité good, G722/16000, PCMA/8000 et PCMU/8000 sur les six cibles/scénarios retenus. Chaque rapport a plus de100 paquets RTP reçus et émis, zéro interruption audio. Minima constatés : 392paquets RX et 396TX. Référence audio d’écho disponible ; aucune simple ouverture de port n’est utilisée comme preuve audio.
- Mise à jour native historique003→004 depuis GitHub en143,52s : identité, clé, adoption, mot de passe administrateur, comptes SIP et ports conservés. Rollback effectif vers003, puis remise à niveau par la commande permanente publique. Un cycle supplémentaire conserve trois véritables entrées d’historique local.
- Interruption injectée pendant un téléchargement public : CONTROLLED_FAILURE, aucun faux succès, ancien003 conservé avec le même PID, fichiers partiels nettoyés ; reprise en une commande vers004 avec toutes les preuves persistantes inchangées.
- Sauvegardes réelles contrôlées : identité/configuration/SQLite présents, checksum et quick_check valides, archives0600/dossiers0700. Une copie corrompue est refusée sans restauration.
- update --check, version, status, diagnose, update à version identique et réinstallation depuis GitHub : aucune nouvelle identité, aucun reset de mot de passe ni redémarrage inutile. Un rollback sans version précédente est refusé sur les installations neuves Docker/DSM.
- Redémarrage complet des deux VM et du daemon Docker isolé : démarrage automatique, trois entrées d’historique et preuves d’identité/credentials/ports inchangées, HTTPS/WSS et deux enregistrements SIP rétablis.
- Refus réel des ports HTTP/SIP/RTP occupés, sans arrêter le service occupant. Résultats stricts testés dans des conditions préservant le shell parent avec errexit/PuTTY.
- 79 tests Agent/export public réussis, plus14 tests privés de publication, collecte de sources et renouvellement. Le collecteur reproduit les86 sources Debian exactes et les sept sources Python ; renouvellement du canal qualifié hors ligne, sans modification des assets ni de la racine.

Les essais de pannes supplémentaires du gestionnaire1.0.0 (disque plein, signatures/archives invalides, échec de démarrage, reprise transactionnelle, drainage et rollback Docker entre révisions LAB) restent ceux de sa qualification LAB antérieure. Ils ne sont pas présentés comme un deuxième test matériel Synology ou comme une mise à jour entre deux Releases GitHub futures encore inexistantes. Le vrai changement de version testé depuis GitHub est la transition native003→004. Le rollback neuf Docker sans précédent est volontairement refusé.

## Sécurité, licences et distribution

Sources originales Agent/outillage sous GPL-3.0-or-later, décision WIFX explicite ; tiers sous leurs licences. Les sources PJSIP/Python/NumPy/OpenBLAS et patches Debian correspondant aux130 paquets de l’image sont fournis : 86 paquets sources Debian, 284 fichiers amont reçus et vérifiés,189 entrées SHA256 de .dsc validées. Les recettes et notices originales accompagnent la distribution. Base de l’audit PJSIP : [licence2.16](https://docs.pjsip.org/en/2.16/overview/license_pjsip.html) et [composants tiers](https://docs.pjsip.org/en/2.16/overview/license_3rd_party.html) ; compatibilité Apache2/GPL3 selon [Apache](https://www.apache.org/licenses/GPL-compatibility).

Audit des sources publiques et de tout leur historique, des SDK/wheels, archives et six couches Docker : aucun secret WIFX, code Controller, identité installée, clé de signature privée, credential Registry ou historique Git privé. Les13 archives tierces comportant des fixtures déjà publiques et les six constantes d’autotest de la bibliothèque Debian libgnutls sont des exceptions expressément approuvées, comparées aux sources officielles. Il ne s’agit jamais de clés de production. Aucune clé amont n’est utilisée pour les identités ou signatures Voice Probe.

Les manifests RSA4096/SHA256 utilisent une nouvelle racine de production, distincte du LAB. SPKI SHA256 : `f65020bb2c6139ba381094533afa0a28fbf3b34f7d6203f2a140b9ce999fde55`. Le bootstrap épingle cette clé ; séquence et expiration sont vérifiées. Le canal beta pointe sur ce tag immuable ; aucune image latest, GHCR ou authentification Registry client. Aucun token n’est diffusé.

## Inventaire et SHA-256

| Fichier publié | SHA-256 |
|---|---|
| [agent-manager-c23ff4fce77f.py](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/agent-manager-c23ff4fce77f.py) | `c23ff4fce77f63ff7b0d27a867066a4ef84170097f67e9a4a6543601d29e765c` |
| [bootstrap.manifest](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/bootstrap.manifest) | `eec78696761f9c615cb703940e29dbd784fc33dd04f3391250465350ba72ad5c` |
| [bootstrap.sig](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/bootstrap.sig) | `359b0ab7e021c300e3bfa60322f0cc695c902ef1a2ef2a2b524213e43a3f309c` |
| [corresponding-sources-agent-0.9-004.tar.gz](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/corresponding-sources-agent-0.9-004.tar.gz) | `707461acf9b3d00c27d2e3adb186f540f362329afe5c00b04125ffb5342b8cce` |
| [debian-12-amd64-cp311-a4ebe371e51c.tar.gz](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/debian-12-amd64-cp311-a4ebe371e51c.tar.gz) | `a4ebe371e51ce280bf9d09073fd4664c42658e9dfb1b0d3ca97c3369652aba4f` |
| [install.sh](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/install.sh) | `ca74b29488edd2088f2b2eb92c244c7e2dd4c4f4de2ec574a7dc6da4d31c67fa` |
| [release.json](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/release.json) | `a78655d306340c71834cd621da5e721532ab375374fac85f8a5178ba0d07405f` |
| [release.sig](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/release.sig) | `412308b641224044f9e6091c65516f8838944adb836d4dc88f104c58f729c53c` |
| [signing-public.pem](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/signing-public.pem) | `0b6d197111e40ab88c208c3e0717124b6d4901c0d7297e507bf2f9b467bc0602` |
| [ubuntu-24.04-amd64-cp312-6a05721dc277.tar.gz](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/ubuntu-24.04-amd64-cp312-6a05721dc277.tar.gz) | `6a05721dc277650fba1ec9f248ed0f8227922c181ecfa0adffe9400e350f0ef7` |
| [voiceprobe-agent-0.9-004-d9b46ac98af1.tar.gz](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/voiceprobe-agent-0.9-004-d9b46ac98af1.tar.gz) | `124d08329296fc676ae41a338abf690ec73ede36b505e0ff375f50ca49b4f6e1` |
| [voiceprobe-agent-image-0.9-004-d9b46ac98af1.tar.gz](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/voiceprobe-agent-image-0.9-004-d9b46ac98af1.tar.gz) | `eaadf72c9d074814e85c5b9516a2744bcaea27e6c87f79a17c866600ee54204d` |

[SHA256SUMS](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-004-installer-1.0.0/SHA256SUMS) complète cet inventaire (13assets avec ce fichier). Les archives SDK incluent PJSIP et les dépendances Python ; la même image sert Docker Linux et Synology Intel, sans duplication de binaires par profil.

## Limites et périmètre

Aucun Synology physique, ARM64, Ubuntu22.04, autre Debian, SIP TLS ou réseau IPv6 réel déclaré qualifié. Le profil host doit être confirmé avec les interfaces, le NAT/SDP et le pare-feu du vrai site ; aucun pare-feu global n’est modifié automatiquement. Une évolution des données incompatible est refusée ; aucune migration PostgreSQL n’appartient à l’Agent.

La première racine ne possède pas de rotation automatique : une transition future doublement signée et un gestionnaire qualifié sont nécessaires avant retrait de l’ancienne clé. Le canal doit être renouvelé avant expiration, avec séquence croissante, sans réécrire les assets immuables.

Tous les builds sont locaux. Actions est désactivé selon l’administrateur ; API publique : zéro workflow et zéro run. Aucun workflow/runner/build distant. Neuf nouveaux conteneurs de qualification sont arrêtés, leurs données et disques sont gardés pour reproduction. Les stacks historiques, autres projets et volumes existants sont conservés. Aucun accès opérationnel au Controller WIFX, serveur WIFX, sonde Ubuntu réelle ou NAS réel n’a été effectué.
