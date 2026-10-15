# Synology Intel AMD64

DSM avec Container Manager/Docker, curl et OpenSSL. Le bootstrap détecte Docker dans PATH ou les chemins connus des paquets DSM et choisit un volume /volumeN accessible ; --data-root permet un dossier dédié explicite. Python/systemd ne sont pas requis sur DSM.

Le réseau host est le profil SIP/RTP qualifié en fixture. Aucun mapping bridge n’est présenté comme preuve RTP. Aucun pare-feu DSM global n’est modifié. Le conteneur reste visible dans Container Manager et ses données survivent aux mises à jour.

La qualification est logicielle représentative ; aucun NAS physique ou routage IPv6 DSM réel n’est qualifié. ARM64 n’est pas supporté par ces binaires.
