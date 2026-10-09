/** Rappel des garde-fous, affiché en tête : on ne s'entraîne jamais sur la production. */
export function IsolationBanner() {
  return (
    <div className="notice" role="note">
      <strong>Environnement isolé.</strong> La sandbox tourne sur une machine de
      développement, jamais sur le serveur exposé : le script refuse de démarrer si
      <code> SHIELD_ENV=prod</code>, son réseau <code>sandbox_net</code> n'a aucune sortie,
      et sa base est distincte de celle de production. Les attaques visent uniquement le
      leurre SSH de la sandbox.
    </div>
  );
}
