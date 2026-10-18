# Bêta 0.9-017 — mesures reçues et détail d’exécution

## Audit de la gigue

L’export opérateur du 18 octobre est conservé sous forme d’extraction anonymisée
dans `agent/tests/fixtures/jitter-incident-20261018.json`. Il contient 2999 paquets
RTP comptés par PJSIP, aucune perte RTP, 3001 échantillons d’observateur, 24 trames
manquantes de 10 ms, un MOS-LQ de référence de 4,379 et aucune interruption détectée
sur le signal 1 kHz. Il est distinct de l’exemple initial à trois trames manquantes.
Le rapport original complet et une capture de production ne sont pas disponibles.

Chaîne auditée : PJSIP `pjmedia_rtcp_rx_rtp2` → `pj_math_stat_update` en µs →
PJSUA2 `RtcpStreamStat.jitterUsec` → Agent `ProbeCall.sample`, division par 1000 →
rapport JSON `rtp.rx` → classement Controller, statistiques et notifications.
Les valeurs 6134,609 et 519013 ms sont déjà dans le rapport Agent. Elles ne sont
pas créées par l’affichage ou par une seconde conversion du Controller.

Une reproduction compilée des expressions de PJSIP 2.16 produit exactement
519013 ms sur un flux synthétique à gigue inférieure à 1 ms, au franchissement du
débordement de `timestamp_uint64 * clock_rate`. À une fréquence monotone de 1 GHz
et une horloge RTP de 8 kHz, cette frontière est à environ 26,688 jours. Les
conversions entières ultérieures expliquent la signature du pic. Cette signature
est compatible avec l’incident ; sans uptime ni horodatages par paquet, son
attribution causale à l’appel réel reste non démontrée.

L’observateur livré utilise une différence d’horloges avant conversion, puis la
récurrence de gigue en double. Les 3001 échantillons donnent **0,792850264578 ms**
par pondération exacte des moyennes d’intervalles. Le maximum individuel de cet
ancien export ne peut pas être reconstruit à partir des moyennes ; il reste indisponible. Les différences
de population avec les statistiques PJSIP sont conservées, sans forcer leur égalité.

La méthode `vp-rfc3550-observer-weighted-v1` vérifie méthode, horloge RTP,
SSRC, continuité des fenêtres, exclusions, histogramme, comptes, moments et borne
mathématique de la récurrence. Elle ne plafonne pas la gigue et ne modifie aucun
seuil métier. Un rapport incomplet ou incohérent reste non qualifié, sans retour
automatique aux valeurs PJSIP. La gigue interarrivée comprend les variations
émetteur et locales ; elle n’est pas une attribution au réseau seul.

Les rapports bruts et observations historiques restent inchangés. Les nouvelles
observations enregistrent la méthode et les valeurs brutes. Le détail expose
l’évaluation actuelle séparément de l’observation enregistrée. Les séries de
gigue n’agrègent que les valeurs enregistrées avec la nouvelle qualification.
Les incidents, décisions adaptatives et messages Telegram évaluent les données
exploitables ; un ancien classement critique n’est pas une preuve de gigue valide.
Les pertes RTP, anomalies audio et échecs SIP conservent leurs effets propres.

## Défaut technique reproduit et correction à la source

L’expression originale dans `pjmedia_rtcp_rx_rtp2` est
`ts.u64 = ts.u64 * sess->clock_rate / sess->ts_freq.u64`.
`ts.u64` et `ts_freq.u64` sont des entiers non signés 64 bits ; `clock_rate`
est un entier non signé 32 bits. La multiplication est évaluée en 64 bits avant
la division et se réduit modulo 2^64. Pour 8000 ticks RTP/s, le premier seuil
est `ceil(2^64 / 8000)` ticks monotones, soit 26,68799779 jours à 1 GHz.
C’est l’époque de l’horloge monotone du système qui compte, pas seulement l’âge
du processus Agent. À 10 MHz (exemple QPC Windows), ce seuil est cent fois plus loin.

Le correctif `vp-rtcp-safe-v1`, appliqué au source PJSIP 2.16 épinglé par
`scripts/instrument-pjsip.py`, est livré dans `agent/installer/rtcp-safe.h` :

- Conversion exacte par quotient et reste, avec division binaire lorsque le
  produit du reste dépasserait 64 bits. Seule la réduction modulo 2^32 requise
  par RTP est conservée ; aucune multiplication débordante ni approximation flottante.
- Différences de transit modulo 2^32 puis représentation signée sur 64 bits :
  aucun débordement signé ni négation de `INT32_MIN`. Le demi-tour ambigu est invalidé.
- Accumulateur de gigue en 64 bits ; conversion échantillons→µs en 64 bits.
  Une valeur non représentable dans `pj_math_stat` est invalidée, jamais plafonnée.
- Moyenne et variance PJSIP en précision double ; suppression de la conversion
  du carré d’un écart en µs vers `int`, qui débordait déjà pour certains écarts
  supérieurs à environ 46 ms. Le calcul d’écart type évite également cette réduction.
- Fréquence monotone changée/nulle, recul du compteur et changement d’horloge RTP
  signalés explicitement. Le collecteur vérifie aussi les reculs entre deux arrivées
  et les changements de fréquence. Les statistiques globales invalides deviennent
  `null` dans les nouveaux rapports ; leurs valeurs diagnostiques restent dans
  `jitter_calculation.raw_mean_ms/raw_max_ms`, avec méthode et drapeaux d’invalidité.

Les binaires natifs Debian/Ubuntu, Docker et Windows doivent être reconstruits :
la bibliothèque est liée aux bindings PJSUA2 et sa structure interne change.
Un simple remplacement du Python ne corrigerait pas PJSIP. Les empreintes de
l’instrumentation et du header sont liées aux métadonnées des SDK et des paquets.
L’installation impose le redémarrage normal du service pour charger le nouveau
binaire. Ensuite aucun redémarrage périodique ne sert de contournement : les
sessions commencées après 30 ou 365 jours et celles franchissant l’ancien seuil
sont couvertes, sans modification de l’horloge réelle de la machine de test.

Le maximum PJSIP d’un Agent corrigé n’est accepté par le Controller qu’avec
provenance `vp-rtcp-safe-v1`, validité explicite, population cohérente et borne
arithmétique cohérente avec les transits. Il représente les séquences consécutives
après amorçage. La moyenne principale reste celle du collecteur pondérée par ses
échantillons : le réordonnancement peut conduire PJSIP à sous-échantillonner les
variations. Aucun seuil métier ne change et les vrais pics critiques restent actifs.

### Attribution à l’incident réel

Le défaut logiciel et sa correction sont reproduits sur des données contrôlées.
La valeur exacte 519013 ms et l’ordre de grandeur de la moyenne sont compatibles
avec ce défaut. L’uptime, la fréquence monotone effective et les horodatages par
paquet de l’appel de production manquent : son attribution reste **probable mais
non démontrée**. Aucune donnée historique n’est réécrite pour transformer cette
hypothèse en constat.

## MOS et références

La formule et les coefficients du MOS-LQ de référence restent inchangés. Le
récepteur réel WSOLA n’est pas calibré par le profil G.711 Appendix I. Les pertes
RTP et les effacements après tampon ne sont pas additionnés. Le MOS est inconnu
hors du domaine : Ppl ≤20 %, BurstR ≤8, et Ppl <2 % lorsque BurstR >2.
Les trames manquantes observées restent visibles même si le MOS est indéterminé.
Les seuils de couleur sont centralisés : 4 / 3,6 / 3,1.

Références primaires consultées :

- [RFC 3550, §6.4.1 et A.8](https://www.rfc-editor.org/rfc/rfc3550) : unités RTP et récurrence interarrivée.
- [RFC 3611, §4.7.1–4.7.2](https://www.rfc-editor.org/rfc/rfc3611) : pertes, rejets et rafales distincts ; aucune assimilation du compteur de trames à un rapport XR.
- [G.107 (06/2015), §7.5, tableau 3 note 6 et annexe A](https://www.itu.int/rec/T-REC-G.107-201506-I/en) : formule et domaine validé.
- [G.113](https://www.itu.int/rec/T-REC-G.113/en) : coefficients dépendants du codec, du PLC et de la paquetisation.
- [P.800](https://www.itu.int/rec/T-REC-P.800/en) : évaluation subjective, distincte de cette estimation paramétrique.
- [PJSIP 2.16, rtcp.c](https://github.com/pjsip/pjproject/blob/2.16/pjmedia/src/pjmedia/rtcp.c) : chaîne de calcul auditée.
- [VoIPmonitor, configuration RTP](https://www.voipmonitor.org/doc/Sniffer_configuration) : simulations F1 50 ms, F2 200 ms et adaptative jusqu’à 500 ms ; aucune équivalence chiffrée avec le récepteur réel n’est revendiquée.

## Interface et limites des anciens rapports

Résumé compact et recherche VoIPmonitor manuelle côte à côte, sans appel API
supplémentaire. Synoptique en lecture seule utilisant les identités SIP rapportées,
les comptes prévus et les associations PBX/SBC/Cloud existantes. Les associations
actuelles ne prouvent ni un trajet physique ni la configuration passée.

Deux pistes A→B et B→A identifient le récepteur, avec échelle, largeur et graduations
communes. MOS, gigue, pertes RTP et trames manquantes sont distincts. Survol, clic
et clavier donnent les valeurs et motifs d’indétermination. Les anciennes sondes
n’exportent pas d’ancrage temporel commun : le zéro représente le premier RTP de
chaque réception, sans prétendre à une synchronisation absolue. Les pertes RTP
globales ne sont pas artificiellement réparties dans les fenêtres.

## Qualification

Le banc C est confronté à un oracle rationnel par convolution, indépendant de sa
récurrence : 18 flux déterministes, fenêtres inégales et deux reproductions
d’arithmétique PJSIP. Les PCAP synthétiques et résultats sont conservés dans le
LAB. Ils ne constituent pas des captures de production ni une qualification
subjective du PLC. Les tests antérieurs couvrent aussi les doublons, changements
de SSRC, wraps RTP, exclusions et réceptions concurrentes.

Les preuves finales, comptes de tests, contrôles PostgreSQL et captures Chromium
seront rassemblés dans la distribution qualifiée. Aucun accès de production.
