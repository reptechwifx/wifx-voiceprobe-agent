# Sécurité

Ne publiez jamais de clé privée, token, configuration de sonde, sauvegarde ou mot de passe SIP dans une issue. Signalez une vulnérabilité à WIFX par votre canal de contact privé habituel, avec une reproduction sans secret. Aucun token client n’est nécessaire pour télécharger les Releases.

L’interface locale exige une authentification. Une nouvelle installation écoute sur une IPv4 privée/loopback détectée ; une IPv6 publique et 0.0.0.0 sont refusées comme nouvelle écoute administrative. L’installateur ne modifie aucun pare-feu global. Les écoutes historiques sont conservées.

TLS, signatures et SHA-256 sont obligatoires. Les seuls redirects admis concernent les fichiers du dépôt officiel et les CDN GitHub explicitement autorisés. Ne désactivez pas TLS. Les sources correspondantes et notices sont dans la même Release que les binaires.

Les clés privées de signature sont hors dépôt. Une clé installée ne change jamais silencieusement ; voir docs/signatures.md. Aucun workflow, runner ou build distant n’est utilisé pour les releases.
