# WIFX Voice Probe Bêta 0.9-012

Agent Linux AMD64 0.9-012 : collecte RTP instrumentée, sans changement du routage SIP, des codecs ni du PLC. Les identités et données locales restent conservées par la mise à jour officielle.

Controller et Agents se mettent à jour indépendamment. Les Agents 0.9-009 restent acceptés ; leurs données insuffisantes donnent « Indéterminé ». Le Controller 0.9-011 accepte les nouveaux rapports mais ne sait pas exploiter leur histogramme compact. Mettre le Controller à jour avant d’attendre les nouveaux affichages, sans obligation de mettre à jour la flotte entière.

## Mesures et limites

L’observateur PJSIP 2.16 lit les en-têtes validés à la réception, avant insertion dans le tampon, et les sorties du tampon de lecture. Aucun payload ni capture réseau brute, aucun délai aller simple, aucun changement d’algorithme audio. G.722 emploie une horloge audio de 16 kHz mais des timestamps RTP de 8 kHz, comme PCMA/PCMU. Les pertes RTP en paquets et les pertes de lecture en trames restent deux mesures distinctes.

Le PDV conserve `vp-relative-transit-min-v1` : Tᵢ=(arrivée monotoneᵢ−arrivée₀)−1000(timestamp RTP étenduᵢ−timestamp₀)/8000 ; PDVᵢ=Tᵢ−min(T). Moyenne, P95 nearest-rank et maximum, en ms. L’histogramme de transit utilise des cases de 0,25 ms ; P95 prend la borne supérieure, plafonnée au maximum observé (erreur de quantification ≤0,25 ms). Minimum, maximum et somme ne sont pas quantifiés. Ni synchronisation des horloges ni déduction de latence absolue ; la dérive relative des fréquences reste dans le transit observé, sans correction fictive.

Séquences 16 bits/timestamps 32 bits déroulés, fenêtre de déduplication de 64 séquences, paquets réordonnés uniques inclus, doublons exclus. Les paquets trop anciens sont comptés séparément et exclus. Les pertes n’ont pas d’arrivée et ne sont pas interpolées. Changement de SSRC, discontinuité de timestamp >10 s, transit hors ±2000 ms ou dépassement de durée invalident explicitement le PDV. Le tampon compte les trames normales/manquantes/vides après sa première trame normale ; le préremplissage initial est exclu. Le jitter RFC 3550 par intervalle est la moyenne observée de l’EWMA |Δtransit|/16 ; il ne remplace pas le PDV. Le jitter global RTP/RTCP PJSIP existant est conservé.

Le MOS reste une **estimation paramétrique d’écoute réseau**, jamais subjective, PESQ/POLQA ou équivalente aux MOS F1/F2/Adapt de VoIPmonitor. La méthode 0.9-011 `vp-g107-listening-g711-10ms-v1` reste disponible pour son contrat exact de profils/10 ms. Le PLC G.711 livré par PJSIP est **WSOLA**, pas Appendix I : les coefficients Bpl Appendix I ne lui sont pas attribués. Pour les observations G.711 sans aucune perte en sortie de tampon, l’équation existante se réduit à Ie_eff=0, R=93,2, MOS=1+0,035R+7×10⁻⁶R(R−60)(100−R)=4,409. Bpl est enregistré null et n’est pas nécessaire dans ce cas. Avec pertes WSOLA, ou pour G.722 sans profil G.107.1 qualifié, **MOS estimé : Indéterminé**. Ce plafond sans perte ne détecte pas les défauts acoustiques, de référence ou de transcodage ; alertes 1 kHz, niveau et continuité restent actives.

Intervalles réellement collectés toutes les 2 s et à la fermeture, limités à 320 pour les appels de 600 s ; histogramme de 16001 cases par stream (~64 Kio), aucun paquet conservé. Le détail montre PDV, jitter, pertes de lecture et MOS uniquement là où il est calculable. Une dégradation peut produire une zone de MOS indéterminé, pas une courbe inventée. Référence PDV commune : minimum de tout l’appel. Seuils visuels temporels PDV : ≤20 ms vert, >20 à 50 ms à surveiller, >50 ms dégradé ; trames manquantes signalées séparément en rouge, sans présenter cette couleur comme un MOS mesuré.

Capacité `capabilities.media_quality` : protocole 1, disponibilité effective du binding d’observation, intervalle 2 s, résolution 0,25 ms. Ancien binding, notamment modèles Windows 0.9-009 déjà qualifiés : collecte absente, aucun zéro de remplacement. Les EXE Windows historiques et leur racine CNG/provisioning restent indépendants ; aucune signature Authenticode de production disponible.


## Mise à jour

Utiliser `sudo voiceprobe-agent update --backend native --strict --timeout 180` pour une installation native, ou `sudo voiceprobe-agent update --backend docker --instance default --strict --timeout 180` pour Docker/Synology. Le résultat attendu est `VOICEPROBE_AGENT_RESULT=VERIFIED_SUCCESS`. Aucune mise à jour automatique de flotte. Un matériel Synology physique n’est pas qualifié par les tests Docker AMD64. Les EXE Windows historiques ne sont pas mis à jour par cette commande.
