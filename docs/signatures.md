# Signatures et confiance

Manifestes RSA4096/SHA256 de production. L’empreinte SHA256 SPKI publique est f65020bb2c6139ba381094533afa0a28fbf3b34f7d6203f2a140b9ce999fde55. Le bootstrap épingle cette clé ; TLS authentifie son premier téléchargement officiel. Les clés privées restent hors Git et hors artefacts.

Le canal beta contient les catalogues signés ; chaque catalogue désigne une Release immuable. La séquence ne diminue jamais et l’expiration est contrôlée. Les binaires sont vérifiés par SHA256 après signature. Une autre clé proposée à une installation est refusée.

Rotation : publier d’abord, sous la clé actuellement approuvée, une version du gestionnaire portant la nouvelle racine et une déclaration de rotation signée par les deux clés. Qualifier la transition et conserver les signatures/versions antérieures pendant sa diffusion. Ne retirer l’ancienne clé qu’après qualification et migration des clients. Cette première livraison ne propose pas de rotation automatique : tant qu’une telle version n’a pas été livrée et qualifiée, conserver la racine actuelle ; ne remplacer jamais manuellement la clé à l’aveugle. En cas de compromission, suspendre le canal et annoncer une procédure de récupération authentifiée distincte.
