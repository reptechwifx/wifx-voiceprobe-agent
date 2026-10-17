# Qualification Agent Bêta 0.9-013

Installateur officiel 1.0.2 inchangé. Binaires Linux AMD64 PJSIP/PJSUA2 2.16
Ubuntu 24.04/Python 3.12 et Debian 12/Python 3.11 ; image Docker AMD64.

25 appels SIP/RTP bidirectionnels réels, 50 rapports et 260 vérifications ont
qualifié PCMA, PCMU et G.722, pertes, rafales, réordonnancement et défauts
temporaires. Ces preuves ont été conservées ; aucun appel n’a été rejoué pour
la finalisation de livraison. Les intervalles compacts sont versionnés avec
`distribution_protocol=2` ; le protocole d’observation externe reste 1.

Le Controller 0.9-013 affiche « MOS-LQ estimé · référence G.711 », un modèle
G.711 Appendix I en trames de 10 ms. Il ne prétend pas calibrer le PLC WSOLA
réel de PJSIP. G.722 reste Indéterminé faute de profil G.107.1 qualifié.
L’Agent mesure et transmet les observations ; aucun score acoustique ni délai
aller absolu n’est inventé. Controller 012 et Agent 009 restent compatibles,
avec les limites de représentation antérieures explicitement conservées.

Mises à jour natives qualifiées sur deux clones systemd Ubuntu/Debian ;
Docker Linux AMD64 et profil Docker/Synology qualifiés sur deux copies privées
de données 012 dans un moteur isolé. Gestionnaire officiel inchangé :
012→013 puis nouvelle exécution sans réinstallation, identité, configuration
et historique conservés, HTTPS/WSS connectés. Le miroir TLS de qualification
change seulement le transport signé ; les octets et la signature du candidat
public sont vérifiés séparément. Les adresses de réseau de test sont adaptées
avant la mesure ; les installations d’origine restent inchangées.

Aucun NAS Synology physique testé, aucun ARM64 qualifié. Aucun nouveau binaire
Windows de production : modèles existants conservés, limitations Authenticode
inchangées. Aucune mise à jour automatique ni déploiement de production.
