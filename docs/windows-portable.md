# Windows portable — en cours de qualification

Agent Bêta 0.9-004 · adaptation portable 0.2.0-LAB · Windows x64.

**Aucun EXE destiné aux clients n’est publié.** Le candidat Phase 2 est réservé au laboratoire. Il ne possède pas de signature Authenticode WIFX reconnue. Les Releases Linux/Docker existantes restent disponibles et immuables ; leurs commandes ne changent pas.

## Utilisation préparée pour le technicien

Le Controller prépare une intervention identifiée par une référence `WSUP-` suivie de un à sept chiffres. Le technicien choisit le client, le site et les dates, puis demande un programme personnalisé. La construction doit avoir réellement abouti et le fichier doit avoir été vérifié avant que le téléchargement soit proposé. Les paquets client sont privés ; ils ne sont jamais ajoutés à une Release GitHub publique.

Le parcours Phase 2 prépare **un seul fichier EXE**, avec une préparation signée intégrée et liée au modèle de programme. Aucun JSON séparé n’est remis au client. Ce programme contient Python Windows x64, PJSIP/PJSUA2 2.16 précompilé et le moteur Agent existant. Le client n’a besoin ni de Python, ni de compilateur, ni de Docker ou WSL. L’audio de test est synthétique ; aucun microphone n’est enregistré.

La première ouverture génère une identité locale Windows. L’Agent apparaît en attente d’adoption dans le Controller. WIFX vérifie cette identité avant l’adoption et transmet ensuite les comptes SIP autorisés. Le client ne saisit aucun paramètre SIP et ne reçoit aucun identifiant administratif WIFX.

Ce parcours Controller Phase 2 a été exécuté de bout en bout en LAB avec les EXEs personnalisés réellement téléchargés. Il n’est pas déployé sur le Controller WIFX et n’est pas annoncé disponible aux clients.

## Fenêtre du client

La fenêtre affiche la référence de l’intervention, la connexion WIFX, l’autorisation, l’enregistrement téléphonique, les tests et la durée restante. Elle reste en lecture seule. Aucun serveur HTTP administratif ni API de modification locale n’est démarré.

« Réduire » laisse la sonde travailler et place son icône WIFX dans la zone de notification Windows. L’action de restauration de la fenêtre depuis la notification est implémentée ; la limite de qualification du clic Shell est précisée ci-dessous. Une réduction ne termine pas les appels ni les campagnes. « Quitter » ferme la sonde ; si un appel est actif, une confirmation est demandée avec **Non par défaut**. L’arrêt accepté libère les appels, les connexions et le moteur SIP avant la fermeture.

L’application ne crée aucun service, démarrage automatique, tâche planifiée ou règle permanente de pare-feu. PyInstaller extrait temporairement ses bibliothèques ; les fichiers audio utilisent un répertoire temporaire privé. Ces dossiers sont nettoyés à l’arrêt normal. Une panne ou un arrêt forcé peut laisser des traces ; aucune suppression forensique n’est promise.

## Relancer sans nouvelle adoption

Le mode Phase 2 conserve une identité CNG non exportable dans le profil Windows de l’utilisateur et de petites métadonnées publiques dans HKCU. Fermer l’application conserve cette identité. Relancer le même programme avec le même utilisateur Windows reprend la même clé et le même identifiant ; une nouvelle adoption n’est pas demandée pour une identité déjà adoptée et toujours autorisée.

Les comptes SIP et le bearer de session ne sont pas enregistrés durablement. Une nouvelle session doit obtenir son autorisation et ses paramètres auprès du Controller. Copier le fichier sur un autre PC ou utiliser un autre profil Windows ne transfère pas la clé et ne permet pas de reprendre automatiquement l’identité adoptée. Des métadonnées ou une clé manquantes/incohérentes sont refusées, sans remplacement silencieux de l’identité.

Le mode éphémère de première génération reste distinct : son identité est perdue après fermeture. Il ne faut pas le confondre avec la persistance CNG Phase 2.

## Deux dates, deux contrôles

| Validité | Rôle |
|---|---|
| Invitation | Permet la première demande d’identité/adoption. Une invitation consommée est liée à l’identité qui a prouvé sa clé. |
| Intervention | Autorise les diagnostics dans la période approuvée par WIFX. Son expiration arrête les tests. |

L’expiration d’une invitation ne supprime pas une identité CNG existante. Au relancement, une preuve de possession de cette clé permet au Controller de rechercher l’intervention actuellement approuvée. Un ancien EXE ne prolonge jamais lui-même les autorisations.

WIFX peut prolonger ou réautoriser explicitement une intervention expirée. Une nouvelle intervention sur la même identité conserve l’adoption et possède sa propre référence et son propre historique. Une **révocation de sécurité** de l’identité reste définitive : une simple prolongation ne la réactive pas.

L’Agent utilise un bail serveur de 60 secondes maximum, contrôlé par horloge monotone. Hors connexion, les nouveaux appels sont refusés et les appels actifs sont libérés lorsque le dernier bail expire. La durée complète affichée provient des dates du serveur ; changer l’horloge Windows n’accorde pas d’autorisation.

## Diagnostic

Un REGISTER accepté ne prouve pas le passage de l’audio. Si un appel est établi sans aucun paquet RTP reçu, le message commence par : **« Appel établi, mais aucun média reçu. »** Les causes possibles doivent être vérifiées ; le programme n’attribue pas automatiquement le problème au pare-feu. Une absence de média ne produit pas un MOS inventé.

Un refus d’enregistrement téléphonique, un certificat TLS refusé et une connexion WIFX indisponible ont des diagnostics distincts. Les mots de passe SIP, clés privées et tokens ne sont jamais affichés dans cette fenêtre.

## Nettoyer l’identité locale

La suppression de l’EXE conserve l’identité CNG pour une prochaine intervention. Le paramètre EXE `--forget-identity` déclenche le nettoyage explicite de cette seule instance, avec confirmation Windows sur Non par défaut, sans Python installé, moteur SIP ou connexion réseau. Il a été exécuté sur le candidat LAB : Non conserve la même identité, Oui supprime sa clé et sa feuille HKCU. Fermer d’abord la sonde, puis relancer son fichier EXE avec ce paramètre. Le mode LAB non signé ne devient pas une distribution client par la réussite de ce test. Aucun nettoyage global de clés CNG ou de profils Windows n’est prévu. Le retrait local de la clé ne remplace pas la révocation de l’identité dans le Controller.

## Sécurité, signature et limites

Voir [les garanties et limites Windows](windows-security.md) et [la construction](windows-construction.md).

La préparation signée ne contient aucun compte ni mot de passe SIP. La personnalisation doit précéder une éventuelle signature Authenticode finale ; ajouter une préparation après signature sans en contrôler les conséquences n’est pas un parcours officiel. Les manifestes signés RSA4096 et Authenticode sont des contrôles différents. Aucun certificat de code reconnu n’est disponible pour une livraison client à ce stade.

HTTPS/WSS valident les certificats avec le bundle prévu par le programme ; les racines d’entreprise du magasin Windows ne sont pas reprises automatiquement. Aucun contournement TLS ni modification du pare-feu n’est effectué. Les exigences réseau réelles du client doivent être examinées par WIFX.

## Qualification disponible

Le candidat final Phase 2 a été exécuté sur Windows 11 x64 build 26300, sans élévation, avec Python 3.13.16 et PJSIP/PJSUA2 2.16 embarqués. Les DLL Python/PJSUA2 chargées proviennent de son extraction privée ; aucun Python hôte n’est nécessaire à l’EXE.

Le parcours réel a vérifié : téléchargement privé authentifié d’un EXE seul, empreinte conforme au résultat du worker, préparation intégrée, adoption manuelle initiale, WSS, REGISTER UDP/TCP et trois campagnes automatiques mono-appel, une par codec. G.722, PCMA et PCMU ont tous terminé avec RTP reçu/émis et zéro interruption audio mesurée pendant que la fenêtre était masquée. Deux EXEs Windows distincts sur le même hôte ont aussi effectué un appel entre sondes G.722 avec RTP bidirectionnel et zéro interruption audio. Ce résultat ne qualifie pas deux PC séparés ou tous les NAT.

Fermer puis relancer après expiration réelle de l’invitation a conservé l’identité/adoption. Une nouvelle intervention du même ticket, puis un nouvel EXE personnalisé différent, ont repris la même clé CNG sans nouvelle adoption. Les historiques portent les identifiants distincts de leurs interventions. L’expiration pendant appel avec fenêtre masquée, la réautorisation explicite sans relance et la révocation de sécurité ont été exercées. Une prolongation avec une date future valide ne réactive pas une identité révoquée ; son nouveau paquet ne reçoit pas d’autorisation.

Une coupure du seul gateway LAB a fait expirer les deux baux et arrêté les appels. L’observation finale « deux fenêtres expirées et zéro appel PBX » intervient 60,10 s après le lancement de l’arrêt du gateway ; ce chronomètre inclut les observations et n’est pas aligné sur le dernier bail. Il ne prouve donc pas un arrêt avant 60,00 s. Après restauration, de nouveaux baux authentifiés ont permis la reconnexion et les enregistrements sans changer d’identité.

« Non » puis « Oui » pendant un appel ont vérifié la confirmation avec Non par défaut, le maintien du test après refus et la fermeture propre après accord. La notification est reconnue par Shell_NotifyIconGetRect et le callback natif restaure la fenêtre. **L’activation réelle de l’icône dans le Shell Windows reste à valider manuellement** : l’objet accessible au rectangle fourni était le panneau de barre des tâches, pas une icône identifiée WIFX ; aucun Invoke n’a été effectué sur un objet non identifié WIFX. Les essais de clic au rectangle fourni par le Shell n’ont pas démontré la restauration. Windows peut placer les icônes dans la zone masquée. Cette limite ne remet pas en cause les appels/campagnes effectivement poursuivis en arrière-plan.

Le contrôle CNG a vérifié un refus réel d’export privé, les signatures, la réouverture, les altérations de métadonnées et le nettoyage ciblé. Le stockage mémoire possédé utilise réellement CryptProtectMemory ; VirtualLock a réussi sur la fixture mesurée, sans garantie pour tous les postes. Les essais de diagnostic ont reproduit un REGISTER refusé et un appel établi sans aucun RTP reçu, avec un MOS absent.

Ces essais restent LAB. Aucun EXE client officiel, certificat Authenticode reconnu, Windows Server, IPv6 réel ou qualification complète de PC clients/NAT/pare-feu n’est annoncé. Aucun essai n’a utilisé un Controller WIFX ou une sonde de production. Les preuves de la précédente Phase 1 restent séparées ; elles ne remplacent pas les essais du nouveau candidat.
