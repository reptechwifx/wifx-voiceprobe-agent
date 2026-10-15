# Windows portable — en cours de qualification

Agent applicatif Bêta 0.9-004 ; adaptation portable 0.1.0-LAB. **Aucun téléchargement EXE client n’est publié à ce stade.** Les Releases Linux/Docker existantes restent disponibles et immuables. Aucun certificat WIFX Authenticode n’est disponible : les exécutables construits localement sont des candidats LAB non signés, réservés aux essais autorisés.

Le programme réutilise le moteur SIP/RTP de l’Agent : Python Windows 3.13.16 x64, PJSIP/PJSUA2 2.16 précompilé, signaux synthétiques, aucun microphone nécessaire. Le paquet autonome est construit sous Windows avec PyInstaller ; aucun Python, compilateur, Docker ou WSL n’est requis sur la machine d’exécution. Les outils de construction utilisent WSL/Docker uniquement sur le poste de développement.

## Parcours préparé

Une fois le binaire signé et qualifié, WIFX préparera une invitation depuis son Controller, puis fournira un ZIP privé contenant `WIFX-VoiceProbe.exe` et `WIFX-VoiceProbe.provision.json`. Décompresser les deux fichiers dans le même dossier, ouvrir l’EXE, attendre l’adoption par WIFX, puis laisser la fenêtre ouverte. Aucun paramètre SIP ni identifiant administratif WIFX n’est demandé au client. Le parcours Controller est développé et testé en LAB ; il n’est pas déployé sur le Controller WIFX.

La fenêtre affiche seulement l’application, la connexion WIFX, l’adoption, l’enregistrement SIP, les tests et la durée restante de l’autorisation calculée depuis les données du serveur. Aucun serveur HTTP administratif n’écoute dans ce mode. « Arrêter et quitter » termine les appels, les connexions et le moteur SIP avant de fermer. Supprimer ensuite le ZIP et le dossier extrait. Une invitation utilisée est liée à une seule identité ; relancer après la fin d’une session éphémère nécessite une nouvelle invitation WIFX.

## Données et autorisations

L’identité RSA est générée en mémoire. Les credentials d’adoption et SIP restent en mémoire ; les fichiers audio synthétiques et reçus utilisent un dossier temporaire privé, nettoyé à l’arrêt normal. Le programme n’installe aucun service, autostart, tâche planifiée ni règle de pare-feu. PyInstaller extrait aussi temporairement les bibliothèques nécessaires. Un arrêt forcé, une panne système, la mémoire virtuelle ou les outils de sécurité Windows peuvent laisser des traces ; aucune suppression forensic n’est promise. Un administrateur du PC peut examiner la mémoire.

La signature RSA du provisioning est vérifiée avec une clé publique intégrée au programme. L’invitation ne contient aucun mot de passe SIP ; elle est privée, limitée dans le temps et inutilisable comme accès administrateur. La validation de l’adoption exige une preuve de possession de la nouvelle clé. La copie du paquet ne permet pas de reprendre une identité adoptée.

Le Controller accorde un bail de 60 secondes maximum, compté par horloge monotone à partir du début de la requête. Les appels sont refusés hors autorisation ; les appels actifs sont libérés à expiration ou révocation. Hors connexion, la révocation prend effet au plus tard à l’expiration du dernier bail, sans prétendre arrêter instantanément un PC déconnecté. Révoquer la sonde ne révoque pas les credentials d’un PBX tiers : WIFX doit les désactiver ou les changer à la fin de l’intervention.

## Réseau et limites

HTTPS/WSS vérifient TLS ; aucune option normale ne désactive cette vérification. SIP UDP/TCP et les ports RTP nécessitent un chemin réseau compatible. Le programme ne change pas automatiquement Windows Defender Firewall. Si Windows ou le réseau bloque les flux, le technicien doit examiner le diagnostic et autoriser seulement le périmètre nécessaire. Aucune règle globale ni ouverture permanente n’est créée.

Le mode permanent/service et la persistance DPAPI facultative ne sont pas livrés. Windows Server, IPv6 réel, les PC clients et leurs différents pare-feu/NAT demandent une qualification distincte. Les essais LAB utilisent exclusivement des identités et comptes SIP fictifs et Asterisk ; aucun appel facturé.

## Construction et signature

Voir [la construction PJSIP](windows-construction.md). Les scripts de packaging `agent/windows/build-portable.py`, `build-portable.ps1` et `portable.spec` construisent un EXE unique en mode LAB. Le verrou `requirements-build.lock` impose les wheels exactes et leurs SHA-256 ; aucun fallback de compilation n’est autorisé. La clé privée de provisioning et les invitations ne sont jamais incluses dans le bundle universel.

`sign-authenticode.ps1` prépare une signature avec un certificat de code reconnu, sa clé dans le magasin autorisé et un service de datation HTTPS ; aucune clé PFX ni mot de passe n’est passé dans les arguments. La signature reconnue et datée doit être vérifiée avant distribution. La signature RSA4096 des manifestes de livraison et Authenticode sont deux contrôles distincts. La racine RSA des Releases Linux demeure inchangée.

La personnalisation concerne le fichier de provisioning signé, jamais l’EXE après sa signature. La rotation d’une clé de provisioning nécessite une nouvelle version universelle intégrant la nouvelle clé ou un ensemble de clés approuvées ; aucun certificat fourni par le paquet n’est accepté comme nouvelle racine. Les paquets personnalisés et les clés privées restent hors du dépôt public.

## Essais réalisés en laboratoire Windows

Le candidat local a été exécuté sur Windows 11 x64 build 26300 sans élévation et avec son Python/PJSUA2 embarqué. Adoption manuelle, provisioning, WSS, REGISTER UDP/TCP, trois codecs, écho/RTP, deux instances Windows en appel sonde vers sonde et arrêt pendant appel ont été vérifiés. La révocation a arrêté un appel long en 2,06 s ; une coupure du Controller a arrêté un appel en 56,39 s, dans le bail de 60 s. Expiration et révocation sont affichées séparément. Ces essais ne qualifient pas un PC client, Windows Server ou tous les pare-feu/NAT ; aucun EXE client officiel n’est publié.
