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
