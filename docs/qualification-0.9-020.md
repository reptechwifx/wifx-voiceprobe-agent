# Bêta 0.9-020 — qualification différentielle du DTMF automatique

## Cause et correction

En 0.9-019, `DtmfIdentification::enabledFor()` exigeait un destinataire connu, compatible et dans la même organisation. `RunService::launch()` ne créait la preuve DTMF que pour un scénario « Sonde vers sonde ». Un appel SIP, PSTN ou interorganisation n'obtenait donc aucune commande DTMF et affichait « Identification DTMF non activée pour cette exécution ».

Le Controller 0.9-020 prépare une tentative pour tout appel d'au moins 10 s émis par un Agent annonçant `dtmf_identification.discovery=true`. Un Agent 0.9-019 conserve le protocole direct lorsqu'un destinataire compatible est déjà connu. L'organisation, le type de scénario et le numéro appelé ne conditionnent plus la tentative. Les contrôles d'accès aux rapports des deux participants restent appliqués.

L'Agent 0.9-020 envoie d'abord `*90#` en RTP telephone-event. Si un Agent 0.9-020 répond `*91#`, l'appelant transmet la trame d'identification existante et les deux observations authentifiées confirment l'association. Sans réponse, la trame longue n'est pas envoyée ; l'émission locale reste « sans confirmation distante ». Une destination ordinaire peut interpréter ces quatre touches comme des commandes IVR. Le Controller ne déduit ni réception distante, ni fraude, ni qualité RTP de ce seul résultat.

## Preuves LAB ciblées

- Laravel SQLite : 12 tests, 62 assertions. PostgreSQL 17 : les mêmes 11 tests et 59 assertions ; migration additive avec `receiver_agent_id` et `receiver_account_id` nullables. Les tests couvrent organisation différente, destination sans Agent connu, durée courte, accès au rapport d'une autre organisation, observations authentifiées et rejet des erreurs de preuve. Les tests de corrélation/qualité inchangés : 30 tests, 277 assertions.
- Agent : 13 tests Python réussis, incluant le décodage du préambule sans contamination de la trame longue. Les 16 tests de la distribution Controller réussissent.
- PJSUA2 2.16 réel en LAB, PCMA : appel B2BUA à Call-ID distincts, découverte A→B, réponse B→A, trames complètes, confirmation Controller, 1 000 paquets RTP reçus par chaque Agent, rapport indépendant de chaque côté, ratio tonal 1 kHz de 0,9997, phase audio débutant à 10 s. Preuves : `var/quality020-lab/dtmf/PCMA-discovery-{1,2}/`.
- PJSUA2 2.16 réel en LAB, destinataire sans réponse DTMF : `*90#` envoyé, aucune trame longue, `remote_unverified`, 601 paquets RTP reçus par côté, ratio tonal 1 kHz de 0,9997. Preuves : `var/quality020-lab/dtmf/PCMA-discovery-no-reply-{1,2}/`. Ce scénario ne qualifie pas un réseau PSTN physique.
- Chromium LAB : identification confirmée 2/2, mesure partielle 1/2 et destination externe 1/1 affichées sans erreur JavaScript. La fixture GUI insère synthétiquement les états Controller ; les essais PJSUA2 ci-dessus prouvent séparément le transport. Preuve : `var/quality020-lab/browser/proof.json`.

Les campagnes PJSIP/MOS/PCMU/G.722 de 0.9-019 restent applicables : le SDK et les composants de mesure n'ont pas été modifiés. La traversée d'un carrier ou d'un PSTN physique n'est pas qualifiée par ce LAB. Une émission locale n'en démontre jamais la traversée.
