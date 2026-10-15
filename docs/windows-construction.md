# Construction du moteur Windows x64

État : **construction locale et contrôle natif Windows effectués ; qualification complète et distribution client distinctes**. Une signature de manifeste ne constitue pas une signature Authenticode. Aucun certificat de signature de code WIFX reconnu n’est fourni par ces scripts.

La construction s’effectue sur le poste de développement Marc-Home, dans Docker Desktop Linux avec MinGW-w64. Aucun compilateur, Python ou service Windows n’est installé sur le PC client. Le conteneur de construction n’est jamais distribué.

## Versions et périmètre

| Composant | Version / cible |
|---|---|
| PJSIP/PJSUA2 | 2.16 |
| Python embarqué / ABI | CPython 3.13.16 x64 / `cp313` |
| Compilateur | GCC MinGW-w64 12 POSIX, x86-64 générique |
| SWIG | 4.1.0 |
| Plateforme exécutée en LAB | Windows 11 AMD64, build 26300 |
| Codecs obligatoires vérifiés | G.722, PCMA, PCMU |
| Audio | périphérique nul, sans microphone ni haut-parleurs |
| Transports compilés | SIP UDP et TCP ; SIP TLS absent de ce build |

Les connexions HTTPS/WSS utilisent le moteur TLS de Python et restent vérifiées. La présence de SIP UDP/TCP dans le moteur ne constitue pas à elle seule une qualification d’appels ou du pare-feu client.

## Entrées authentifiées

Le pilote exige l’archive officielle PJSIP 2.16, empreinte SHA-256 :

```text
3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb
```

Le SDK Python doit provenir du paquet officiel CPython NuGet `python/3.13.16`, dont l’empreinte constatée est :

```text
95fad176338f1d6a799e45946488063f4aa61764e6cff2f132ddeffbf7a04c34
```

Les en-têtes Python, la bibliothèque d’import et `python313.dll` doivent provenir ensemble de ce paquet. Le pilote vérifie les en-têtes 3.13 et l’architecture PE AMD64. L’acquisition du SDK doit vérifier TLS, la provenance et cette empreinte avant extraction.

## Commande de construction réservée au développement

Depuis la racine des sources, avec les entrées préparées et des destinations inexistantes :

```sh
VOICEPROBE_CONTROLLED_BUILD=marc-home python3 agent/windows/build-pjsip-windows.py --source var/windows-agent/pjproject-2.16.tar.gz --python-sdk var/windows-agent/python-nuget/tools --output var/windows-agent/pjsip-sdk --work var/windows-agent/pjsip-build
```

Les chemins sont des exemples de travail locaux, sans URL de téléchargement Windows client. Le script PowerShell `agent/windows/build-pjsip-windows.ps1` permet de lancer ce même pilote via une distribution WSL explicitement choisie. WSL et Docker ne sont requis que sur le poste de construction.

Le constructeur utilise une base Debian figée par digest, puis consigne les versions effectives des paquets, du compilateur et de SWIG. Les dépôts de paquets évoluent : ces reçus permettent de comparer une reconstruction, sans promettre une identité binaire entre des environnements différents.

## Sorties et contrôles

Le SDK contient uniquement `_pjsua2.pyd`, `pjsua2.py`, `libwinpthread-1.dll`, les notices et la provenance. Le runtime C++ GCC est lié statiquement. Les DLL système Windows et Python ne sont pas copiées depuis une installation personnelle.

Le pilote refuse les chemins d’archives sortant de leur racine, les liens, les fichiers spéciaux, un SDK incorrect, une destination existante et une dépendance DLL inconnue. Le SDK conserve les SHA-256 des fichiers produits. `binary.json` indique `windows_qualified: false` jusqu’à la qualification complète indépendante.

Sur Windows réel, depuis Python 3.13 x64 :

```powershell
python.exe agent/windows/check-pjsip-windows.py --module-dir var/windows-agent/pjsip-sdk --report pjsip-check.json
```

Ce contrôle charge réellement le binding puis exécute `libCreate`, `libInit`, `libStart`, la sélection du périphérique audio nul, l’énumération des codecs et `libDestroy`. Il ne contient aucun compte SIP et n’effectue aucun appel. Les essais REGISTER, Digest, RTP, écho, concurrence, adoption et révocation sont consignés séparément dans le rapport de qualification.

## Licences et limites de distribution

PJSIP conserve sa licence GPL-2.0-or-later et les licences de ses composants tiers ; les sources originales de l’Agent et son outillage sont GPL-3.0-or-later. Le SDK fournit `COPYING.pjsip`, `COPYING.mingw-w64` et `COPYING.gcc-runtime`. Le runtime winpthreads utilise principalement Expat/MIT, avec les notices spécifiques BSD/domaine public des fichiers concernés. Les runtimes GCC conservent la GPL avec GCC Runtime Library Exception applicable. Les tests winpthreads sous LGPL ne sont pas le runtime distribué.

Une publication binaire doit inclure les notices et sources correspondantes applicables, ainsi que les licences Python et des dépendances réellement embarquées par le packager. Le moteur construit n’inclut pas de secrets WIFX, de compte SIP ou de clé de signature. Le contrôle de marqueurs de clés privées sur le module, le wrapper et winpthreads n’en a trouvé aucun ; ce contrôle complète l’audit général du paquet.

Références officielles : [construction Windows PJSIP](https://docs.pjsip.org/en/2.16/get-started/windows/build_instructions.html), [licences PJSIP](https://docs.pjsip.org/en/2.16/overview/license_pjsip.html), [GCC Runtime Library Exception](https://www.gnu.org/licenses/gcc-exception-3.1.html).

## Essais SIP/RTP Windows du moteur partagé

Un second harnais `agent/windows/qualify-sip.py` utilise directement `main.Agent`, `ProbeAccount`, `ProbeCall` et les fonctions d’analyse audio existantes. Il exige Windows AMD64 et une fixture privée dédiée ; sa destination est fixée au seul PBX LAB `127.0.0.1:5068`, extension d’écho `*777`. Les mots de passe ne sont jamais des arguments de commande. Aucun serveur HTTP administratif ni connexion Controller n’est démarré par ce harnais.

Sur Windows 11 build 26300 / CPython 3.13.16, les résultats observés sont :

| Essai | Résultat |
|---|---|
| REGISTER avec authentification Digest | UDP et TCP, réponse 200 |
| Écho G.722 / PCMA / PCMU | 6 appels validés, les 3 codecs sur chacun des 2 transports |
| Concurrence | 2 appels d’écho simultanés validés |
| RTP réellement reçu / émis | 346–397 / 350–401 paquets par appel |
| Rapport du signal synthétique 1 kHz | 0,9887–0,9897 |
| Corrélation des marqueurs d’écho | 0,8948–0,9049 |
| Délai audio d’écho mesuré | 20 ms G.722 ; 40 ms PCMA/PCMU |
| Interruptions audio détectées | 0 seconde |
| Fin de session | 0 appel et 0 contact restant sur le PBX LAB |
| Contrôle des 4 secrets de fixture dans journal et rapport | 0 occurrence |

Ces mesures proviennent de compteurs RTP/RTCP et du PCM enregistré par le moteur ; aucune capture PCAP n’a été réalisée dans cet essai. Le RTT RTCP brut, par exemple 356 ms sur un appel G.722, est conservé séparément du délai audio d’écho. Il ne faut pas les présenter comme une même mesure. La topologie utilise le renvoi de ports loopback Docker Desktop et ne qualifie pas à elle seule le NAT ou le pare-feu d’un poste client.

Ces résultats qualifient le moteur source Windows dans ce LAB. La qualification de l’EXE complet, du provisioning, de la révocation et de sa distribution possède son propre rapport ; les essais moteur ne la remplacent pas.

## Paquet personnalisé unique — outillage portable 0.2.0 LAB

Le template universel PyInstaller reste sans invitation personnelle. L’outil `agent/windows/personalize-portable.py` ajoute une enveloppe ASCII bornée contenant le provisioning v2 signé. L’enveloppe lie l’identité de préparation, son nonce et le SHA-256 exact du template autorisé. Aucun mot de passe SIP n’entre dans ce paquet. Une invitation est un droit d’enrôlement limité ; elle n’est pas un accès administrateur et ne dispense jamais de l’adoption ni de l’autorisation de test renouvelée.

La table PE AMD64, les sections, la table des certificats, le cookie CP313 et les entrées CArchive sont contrôlés. Les duplications, troncatures, données finales injectées, empreintes divergentes et destinations existantes sont refusées. La personnalisation d’un template déjà personnalisé ou signé est refusée. Le format n’ajoute aucun second cookie binaire susceptible de détourner le chargement PyInstaller. La présence structurelle d’un certificat n’est jamais présentée comme une signature de confiance valide.

Le worker dédié reçoit uniquement un job JSON privé et un catalogue administrateur. Commande interne fixe :

```sh
python3 agent/windows/personalize-portable.py --job job.json --catalog catalogue.json --output paquet-nouveau
```

Le job ne fournit ni chemin de template, ni commande, ni racine de confiance. Le catalogue fixe ces valeurs et leur empreinte. La clé privée de provisioning reste exclusivement dans le worker de signature distinct de l’application Web. L’outil Python vérifie la signature avec la clé publique ; il n’a besoin d’aucune clé privée. La sortie contient `WIFX-VoiceProbe.exe` et un reçu privé `result.json`. Seul l’EXE est transmis au destinataire autorisé. Aucun paquet personnalisé ne doit être publié sur GitHub.

Le mode `production` échoue actuellement avec `SIGNING_NOT_CONFIGURED`. Le mode `lab` produit un binaire **non signé Authenticode, réservé au technicien et au laboratoire**. Il ne constitue pas une distribution client. L’Agent extrait son provisioning intégré ; les anciens fichiers voisins `.provision.json` ne sont pas chargés par cette nouvelle entrée.

Les données officielles WIFX du répertoire `assets` sont embarquées ; aucune image ni police n’est téléchargée au lancement. Le moteur PJSIP qualifié est réutilisé sans reconstruction. Le constructeur compare les empreintes de toutes les sources et ressources avant et après construction.

La compatibilité de l’overlay avec le bootloader a été exécutée sur Windows réel en ajoutant un document synthétique à un EXE QA : auto-test CPython 3.13.16 / PJSIP 2.16 / audio nul / trois codecs réussi. Cet essai ne remplace pas la qualification du nouveau template complet et de l’adoption intégrée.

Références de format : [CArchive et lancement PyInstaller](https://pyinstaller.org/en/stable/advanced-topics.html), [structure PE et Authenticode](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## Signature Windows future et renouvellement de confiance

L’ordre obligatoire est : construire et auditer le template → personnaliser et vérifier le provisioning → signer l’EXE final → vérifier chaîne de confiance, éditeur attendu et horodatage → vérifier à nouveau le format intégré et exécuter le binaire signé. Toute personnalisation ultérieure impose une nouvelle signature ; le système ne modifie jamais un EXE signé pour y injecter une configuration.

Azure Artifact Signing Public Trust est une option à provisionner. La documentation Microsoft actuelle admet les organisations suisses, ce qui ne prouve pas l’éligibilité ou la validation de WIFX SA. Il reste à fournir un tenant et un abonnement Azure, valider l’identité légale et créer un profil Public Trust. Aucun compte, abonnement ou certificat n’a été créé dans ce chantier. Un profil Private Trust ou Public Trust Test ne doit pas être présenté comme reconnu pour la distribution client. Voir [prérequis et validation d’identité](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart).

Le script `sign-azure-artifact.ps1` prépare l’interface de signature, désactivée sans qualification explicite. Il attend un SignTool et une DLL de signature administrés, des métadonnées locales limitées au compte/profil/endpoint Azure HTTPS, et une identité de service externe à l’application Web. Il n’accepte aucun secret dans ses arguments. L’attribution du rôle de signature doit se limiter au seul profil dédié. Aucune installation de SDK, Visual Studio ou modification des stratégies Windows n’est effectuée.

Après signature, le script exige une signature Windows valide, le nom exact de l’éditeur attendu et un certificat d’horodatage. Le service utilise des certificats de courte durée ; l’horodatage est nécessaire. L’endpoint HTTPS d’horodatage Microsoft est documenté. L’adaptateur reste **non qualifié**, sans accès réel Azure ; il n’est pas raccordé au worker de production. Références : [intégration Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations), [exemple Microsoft d’horodatage HTTPS](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide).

Les signatures de manifestes RSA4096 Linux, de provisioning Windows et Authenticode répondent à des objectifs différents. La confiance HTTPS continue d’utiliser la validation TLS et l’origine autorisée. Aucun certificat auto-signé n’est ajouté au magasin système. Une future rotation de racine de provisioning ou d’épinglage SPKI réseau devra être explicitement signée par une racine déjà autorisée, bornée dans le temps et qualifiée avant activation ; aucun renouvellement implicite ou contournement TLS n’est implémenté.

## Suppression explicite de l’identité Windows

Pour un paquet personnalisé privé, après fermeture de la sonde, le même EXE fournit la commande suivante depuis son répertoire :

```powershell
.\WIFX-VoiceProbe.exe --forget-identity
```

Adapter uniquement le nom si le fichier a été renommé. Cette commande vérifie à nouveau le provisioning intégré et sa liaison au template autorisé, puis demande une confirmation native avec **Non par défaut**. Elle supprime seulement la clé CNG et la métadonnée HKCU de cette instance signée. Elle refuse une identité occupée, incorrecte ou absente ; elle ne crée jamais de clé pour effectuer ce nettoyage. Aucune recherche globale d’instances, aucun moteur SIP et aucune connexion réseau ne sont nécessaires. Les autres sondes restent intactes. Une annulation retourne 2 sans afficher de succès ; un refus retourne 1 ; seule une suppression confirmée réussie retourne 0. Fermer le programme ne supprime pas l’identité persistante : utiliser cette commande avant d’effacer le fichier si cette identité n’est plus utile.
