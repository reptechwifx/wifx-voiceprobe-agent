# Qualification Agent 0.9-007 — gestionnaire 1.0.1

Release : [agent-0.9-007-installer-1.0.1](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/tag/agent-0.9-007-installer-1.0.1). Sources construites : `23ee1114953639972e72c3f1cc0e79eb71deb14d`, dans l’historique public Agent uniquement. Les commits documentaires ultérieurs ne reconstruisent pas ces artefacts immuables.

Mettre à jour le Controller vers 0.9-007 avant les Agents. Les commandes d’installation et de mise à jour du README utilisent le canal bêta signé et les fichiers publics de la Release, sans token ni Registry privé client.

| Cible | Qualification de cette version |
|---|---|
| Ubuntu 24.04 AMD64 / Python 3.12 | Mise à jour native systemd réelle 0.9-004 → 0.9-007 depuis GitHub, rollback et réapplication ; identité, adoption, accès administrateur, comptes SIP et ports conservés |
| Debian 12 AMD64 / Python 3.11 | Même transition réelle, conservation et vérifications |
| Docker Linux AMD64 | Installation neuve du candidat signé ; transition réelle 0.9-004 → 0.9-007 depuis GitHub, rollback et réapplication ; deux comptes UDP/TCP enregistrés |
| Synology Intel AMD64 | Même image et mécanisme Docker ; profil logiciel représentatif antérieurement qualifié, aucun NAS physique |
| Windows 11 x64 | EXE 0.3.0-LAB exécuté réellement ; Python embarqué 3.13.16 ; aucun EXE client publié dans cette Release |

PJSIP/PJSUA2 2.16, runtimes précompilés et dépendances de la livraison précédente réutilisés sans modification. Aucune compilation sur les cibles. Les installations natives vierges du même installateur et des mêmes runtimes ont été qualifiées en 0.9-004 ; elles n’ont pas été répétées pour cette évolution du moteur Agent.

Deux sondes réelles sur Asterisk LAB : From réécrit, Call-ID changé, en-tête propriétaire supprimé ; trois codecs G.722/PCMA/PCMU, RTP émis et reçu, signal synthétique observé, réponse automatique environ une seconde. Appels entrants non préparés, compte sortant seul, écho entrant/sortant, panne Controller puis synchronisation et distinction SIP 200 sans média / SIP 488 sont vérifiés. Aucun trunk, numéro facturé ni compte SIP de production.

Windows : trois codecs, REGISTER UDP/TCP, appels et campagne pendant la réduction dans la zone de notification, identité CNG identique après relancement, expiration, prolongation, révocation et fermeture complète. Authenticode indisponible : uniquement des EXE de développement préparés par le Controller, avec provisioning signé. Les EXE personnalisés restent privés.

Le gestionnaire refuse le retour vers 0.9-003/004 tant qu’un rapport entrant autonome reste à transmettre. Ce refus a été déclenché avec un vrai appel et une panne de transport de rapport : même conteneur actif, puis synchronisation après rétablissement.

Mesures LAB : les cycles mise à jour / rollback / réapplication natifs prennent 26,88 s sur Ubuntu et 26,21 s sur Debian. Docker : installation du candidat via HTTPS LAB 14,54 s ; mise à jour publique 22,84 s, rollback 17,08 s et réapplication 26,43 s. Ces durées dépendent du réseau, des caches et du matériel.

Treize fichiers publiquement téléchargés, TLS et signatures RSA4096/SHA256 vérifiés. Audit de 13 780 fichiers imbriqués et huit couches Docker : aucun secret, code Controller ou identité existante. Les seules constantes de clés tierces sont les six autotests publics libgnutls exacts déjà autorisés. Les licences et sources tierces restent celles des composants inchangés, disponibles dans l’archive correspondante ; les sources Agent de cette version sont dans son tag public.

Suite Agent : 171 tests sur Linux, dont 13 ignorés car ils nécessitent Windows ; ces tests ignorés ne sont pas présentés comme réussis. Essais Windows réels distincts réalisés. Aucun pipeline ou build distant, aucune intervention de production.

Limites : pas de NAS Synology physique, IPv6 réel, Ubuntu 22.04, autre Debian ou ARM64 qualifié. Pas de signature Authenticode officielle. Un ancien EXE ne se modifie pas à distance ; son remplacement reste une opération explicite. Autres fréquences et bruit rose non développés.

## Intégrité

[SHA256SUMS de la Release](https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-0.9-007-installer-1.0.1/SHA256SUMS). Racine de signature RSA4096 : SPKI SHA-256 `f65020bb2c6139ba381094533afa0a28fbf3b34f7d6203f2a140b9ce999fde55`. Les SHA-256 sont authentifiés par les manifestes signés ; TLS reste activé.
