# Diagnostic

Commandes : sudo voiceprobe-agent status ; sudo voiceprobe-agent diagnose ; sudo voiceprobe-agent version ; sudo voiceprobe-agent help. Elles ne doivent afficher ni clés ni mots de passe SIP.

Un succès est annoncé après service, interface, version/build, SIP, Controller HTTPS/WSS et comptes enregistrés attendus. Un simple code zéro du lanceur protecteur n’est pas un succès vérifié. Utiliser --strict sous un if pour l’automatisation.

Un mot de passe perdu se réinitialise explicitement avec sudo voiceprobe-agent reset-password. Une mise à jour ne le change jamais. Une nouvelle installation interrompue avant sa remise peut être reprise avec install --reset-initial-password, uniquement si elle n’a jamais été validée.

Avant un arrêt/désinstallation, terminer les appels. En natif, sudo systemctl disable --now voiceprobe-agent.service arrête et désactive l’Agent en conservant binaires/données pour reprise. En Docker, sudo docker stop voiceprobe-agent-default arrête seulement cette instance ; adapter le nom à l’instance réellement installée. Ne jamais supprimer les volumes/données pour mettre à jour.
