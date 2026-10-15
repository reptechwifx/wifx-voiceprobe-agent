# Mise à jour et reprise

Après installation : sudo voiceprobe-agent update. Contrôle seul : sudo voiceprobe-agent update --check. Rollback : sudo voiceprobe-agent rollback. En cohabitation, voiceprobe-agent-native ou voiceprobe-agent-docker choisit explicitement le mode. Ajouter --instance NOM pour une instance Docker nommée.

Les données, identité, adoption, comptes, accès et ports sont conservés. Les artefacts sont préparés/vérifiés avant arrêt ; les appels se terminent avant bascule. Un délai dépassé reporte l’opération. Aucune suspension globale des campagnes distantes n’est promise. Les sauvegardes 0700/0600 contiennent des secrets et ne doivent pas être publiées.

Après interruption, relancer la même commande. Un schéma local incompatible ou une sauvegarde corrompue bloque la reprise plutôt qu’une restauration destructive. Les mises à jour planifiées restent désactivées par défaut ; enable-schedule et disable-schedule sont des choix explicites.

Le lanceur protecteur peut retourner zéro après un échec. Pour automatiser : if sudo voiceprobe-agent update --strict; then printf 'Mise à jour vérifiée.\n'; else printf 'Échec contrôlé.\n' >&2; fi

Pour0.9-007 : Controller d’abord, Agents ensuite. Un EXE Windows020 déjà envoyé conserve son ancien moteur ; générer un nouveau modèle030 en conservant l’instance CNG autorisée. Le rollback vers003/004 est refusé tant que des rapports entrants autonomes attendent leur synchronisation. Le retour applicatif du Controller exige d’abord les anciens binaires Linux et la quarantaine des autorisations Windows ; suivre le guide privé d’exploitation.
