/**
 * Procédure d'arrêt d'urgence (US-48). Volontairement sans bouton : couper
 * l'exposition se fait sur l'hôte, par une personne qui sait ce qu'elle coupe, et
 * aucune action destructive ne doit être déclenchable depuis un navigateur.
 */
export function EmergencyStop() {
  return (
    <div className="emergency">
      <p>
        En cas d'incident (signalement d'abus de l'hébergeur, comportement anormal d'un
        leurre), coupez l'exposition sur le serveur. Les données sont conservées.
      </p>
      <pre className="payload">./scripts/emergency_stop.sh</pre>
      <p className="muted">
        Redémarrer ensuite : <code>docker compose start decoy-ssh decoy-http decoy-ftp</code>
      </p>
    </div>
  );
}
