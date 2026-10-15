# Windows portable — sécurité et limites

Ce document décrit le candidat 0.2.0-LAB. Il ne constitue pas une annonce de disponibilité client. Le parcours opérateur est décrit dans [Windows portable](windows-portable.md).

## Identité persistante CNG

L’Agent utilise une clé RSA3072 du **Microsoft Software Key Storage Provider**, dans le périmètre de l’utilisateur Windows. La politique d’export est nulle et l’usage est limité à la signature. L’Agent n’exporte jamais la clé privée. Les signatures d’enrôlement gardent le contrat RSA-PKCS1v1.5/SHA256 déjà utilisé par le Controller.

Windows conserve les données privées nécessaires au fournisseur CNG dans le profil utilisateur. La clé n’est donc pas une identité uniquement en RAM. HKCU contient seulement le schéma, l’identifiant d’instance, l’identifiant Agent, l’adresse Controller, le nom exact de clé, son empreinte publique et une preuve CNG d’intégrité sur ces métadonnées. Aucun mot de passe SIP, bearer, client ou secret d’invitation n’y est ajouté.

La réouverture vérifie la politique de la clé, l’empreinte, les métadonnées authentifiées et les éventuelles identité/empreinte attendues dans le paquet signé. Une incohérence provoque un refus ; aucun remplacement implicite de clé ou d’identité n’est lancé. Un verrou limite les ouvertures concurrentes d’une instance dans la session Windows.

Le nettoyage explicite vise le nom exact de cette instance. Il vérifie de nouveau les métadonnées et l’empreinte avant de supprimer sa clé et sa seule feuille HKCU. Aucun parcours d’énumération/suppression de clés étrangères n’est utilisé. Le nettoyage intégré dans l’EXE LAB a été testé avec Non puis Oui : conservation de la même identité après refus, puis clé indisponible et feuille HKCU supprimée après accord, sans moteur SIP ni réseau.

La non-exportabilité CNG est une politique du fournisseur Windows. Elle ne rend pas un poste contrôlé par un administrateur local ou un logiciel malveillant digne de confiance. Voir les contrats Microsoft : [stockage CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-key-storage-functions), [politique d’export et usages](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers) et [signature NCrypt](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash).

## Secrets de session et mémoire

Le bearer, l’admission et les motifs secrets utilisés pour masquer les journaux disposent d’un stockage possédé chiffré avec `CryptProtectMemory`, option `SAME_PROCESS`. Le buffer principal est reprotégé immédiatement après la copie nécessaire à un emprunt. Les copies mutables possédées sont mises à zéro à la fin de leur portée ; les allocations sont mises à zéro avant libération. `VirtualLock` est essayé sans augmenter les quotas ou modifier les paramètres Windows. Sa réussite sur une fixture LAB n’est pas une garantie pour toutes les machines.

Les bibliothèques ont besoin de copies pendant leur utilisation : chaînes JSON temporaires, en-têtes requests/websockets, configuration SIP active et credentials natifs PJSIP pour Digest. **Ces copies ne sont pas toutes chiffrées ni effaçables de manière fiable par CPython.** Le marqueur durable de comparaison de configuration portable conserve uniquement SHA256, et non une seconde copie JSON des mots de passe. Une empreinte ne chiffre pas la configuration active, qui reste nécessaire au moteur.

Aucun mot de passe SIP ni bearer n’est persisté volontairement. Les journaux conservent seulement des événements expurgés. Les fichiers temporaires servent aux bibliothèques embarquées et à l’audio de test, avec un dossier de session restreint à l’utilisateur et SYSTEM. Une panne, un dump, l’hibernation, la mémoire virtuelle ou un outil de sécurité peut conserver des traces. Aucune résistance absolue à la lecture mémoire ou à un administrateur local n’est annoncée.

Contrats Microsoft : [CryptProtectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory) et [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

## Préparation, identité et autorisation

Le document v2 intégré au programme est signé par une clé de préparation WIFX distincte de la signature de code Windows et des manifestes de livraison. Sa signature, la clé publique épinglée, l’architecture/version et sa liaison à l’empreinte du modèle/nonce sont vérifiées. Un paquet ne peut pas fournir sa propre nouvelle racine de confiance.

L’invitation permet l’admission initiale, avec preuve de possession de la clé locale et adoption WIFX manuelle. Elle n’est pas un accès administrateur. Une invitation copiée ne transfère pas la clé CNG déjà liée. L’expiration de l’invitation est distincte de celle de l’intervention ; seule une réponse authentifiée du Controller peut accorder un bail opérationnel.

Le bail est limité à 60 secondes et compté depuis le début de la requête par horloge monotone, en incluant le temps réseau. Les réponses anciennes ou arrivées dans le désordre ne prolongent pas l’autorité. Les commandes v2 doivent porter l’identifiant de l’intervention actuellement autorisée. L’expiration bloque les nouveaux appels et libère les appels actifs. Une nouvelle réponse serveur peut réautoriser une intervention explicitement prolongée ; une révocation de sécurité reste terminale.

Révoquer l’Agent ne désactive pas des credentials sur un PBX tiers. WIFX doit aussi désactiver ou changer ces credentials lorsque le contexte de l’intervention l’exige.

## Transport et interface locale

HTTPS/WSS vérifient TLS. L’origine Controller est préconfigurée dans la préparation authentifiée. Les redirections HTTP et WSS sont refusées et les paramètres proxy de l’environnement ne sont pas hérités automatiquement. Le bundle certifi utilisé par le programme ne reprend pas automatiquement les autorités d’entreprise du magasin Windows ; le LAB utilise sa CA dédiée et explicitement embarquée.

Aucun épinglage réseau SPKI ni mécanisme garantissant la confidentialité face à un hôte compromis n’est annoncé. La signature de préparation ne remplace pas TLS. Ne pas ajouter une CA inconnue ou désactiver les vérifications pour contourner une erreur de connexion.

Aucun serveur HTTP administratif n’est démarré par le mode portable. La fenêtre ne reçoit qu’une liste de champs de statut autorisés et ne propose aucun réglage SIP ou Controller. Le client peut volontairement réduire, restaurer ou arrêter la sonde. Aucun service, autostart, tâche planifiée ou règle globale de pare-feu n’est installé.

## Distribution et qualification

Un manifeste signé RSA4096 vérifie une livraison ; Authenticode authentifie un éditeur de programme Windows. Ces signatures ont des objectifs différents. Le candidat reste LAB et non signé Authenticode ; aucun lien client inexistant ni Release Windows de production n’est annoncé.

Les tests natifs Windows vérifient les propriétés CNG, un refus réel d’export privé, les signatures, la réouverture, les altérations de métadonnées, le nettoyage isolé, `CryptProtectMemory`, les copies mutables et la libération. Les tests SIP source utilisent uniquement Asterisk LAB et des comptes fictifs. Le parcours Controller v2 a aussi été exécuté sur les EXEs personnalisés finaux réellement téléchargés : adoption, trois campagnes codecs, reprise CNG avec ancien puis nouvel EXE, réactivation, historiques distincts, paire Windows, perte du gateway, révocation et refus de prolongation avec une date valide. Ces essais réels sont distingués des tests source utilisant un bail de fixture. La restauration physique par l’icône du Shell reste non qualifiée ; seuls son enregistrement Shell, son callback et la poursuite des tests en arrière-plan sont prouvés. La signature Authenticode et les PC clients restent hors qualification.
