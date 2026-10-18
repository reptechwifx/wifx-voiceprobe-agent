# Agent Bêta 0.9-019 — qualification et limites

Le Controller prépare un code temporaire par tentative entre deux Agents qui
annoncent la capacité DTMF version 1. L'Agent appelant l'émet via RTP
telephone-event ; l'Agent destinataire rapporte sa réception au Controller
authentifié et renvoie un second code. L'appelant rapporte la réception de
cette réponse. Les deux observations sont requises pour confirmer l'identité
bidirectionnelle. Les SIP Call-ID peuvent différer entre les jambes d'un PBX.

La trame comporte 15 symboles, dont dix chiffres aléatoires et un contrôle
modulo 97. Elle expire et ne sert pas de mot de passe SIP. Un code transmis ne
prouve pas sa réception. Sans DTMF transporté et validé, le Controller conserve
les rapports indépendants et n'annonce aucune identification certaine. Aucun
appel externe n'est déclaré frauduleux pour la seule absence de DTMF.

Les essais LAB avec PJSUA2 2.16 réel couvrent PCMA, PCMU et G.722, un relais
B2BUA à Call-ID différents, Asterisk avec deux comptes enregistrés, les pertes
DTMF par direction, la duplication d'événements RTP, la négociation SDP sans
telephone-event et un Agent sans DTMF. Chaque Agent produit son propre rapport
RTP. Les tests logiciels et PostgreSQL du Controller couvrent la détection des
appels similaires, les codes concurrents, l'expiration et le rejeu. Les dix
premières secondes DTMF sont exclues des mesures de signal audio 1 kHz et des
effacements de lecture audio opérationnels ; les compteurs complets restent
dans le diagnostic. Le MOS de référence G.711 n'est pas appliqué à G.722.

La Release conserve exactement les binaires PJSIP 2.16 et le correctif
arithmétique de 0.9-017. Les plateformes visées sont Debian 12 AMD64,
Ubuntu 24.04 AMD64, Docker Linux AMD64 et le profil logiciel Synology
Intel/AMD64 via Docker. Aucun NAS physique, réseau opérateur public, ARM64 ou
Raspberry Pi n'a été qualifié pour cette version. Le portable Windows reste
LAB sans signature Authenticode de production. Une mise à jour 0.9-017→0.9-019
utilise le gestionnaire signé existant et conserve les données persistantes.
