import { useState } from "react";

const SCENARIOS = {
  libre: "Libre — l'attaquant choisit ses techniques",
  "bruteforce-ssh": "Force brute SSH — dictionnaire d'identifiants",
  "identifiants-par-defaut": "Identifiants par défaut — admin/admin, root/toor…",
  "balayage-lent": "Balayage lent — sous les seuils de fréquence",
} as const;

type Scenario = keyof typeof SCENARIOS;

/**
 * Déroulé d'une partie, commande par commande. La sandbox se pilote par
 * `scripts/sandbox.sh` sur la machine de développement : aucune commande n'est
 * exécutée depuis le navigateur.
 */
export function SandboxControls() {
  const [scenario, setScenario] = useState<Scenario>("bruteforce-ssh");
  const steps = [
    { who: "Défenseur", what: "Démarrer la partie", command: `./scripts/sandbox.sh start --scenario ${scenario}` },
    { who: "Attaquant", what: "Entrer dans le conteneur attaquant", command: "./scripts/sandbox.sh attacker" },
    { who: "Attaquant", what: "Cibler le leurre de la sandbox", command: "sandbox-decoy-ssh:2222" },
    { who: "Défenseur", what: "Relever le bilan de la collecte", command: "./scripts/sandbox.sh report" },
    { who: "Défenseur", what: "Arrêter et effacer les données d'entraînement", command: "./scripts/sandbox.sh stop" },
  ];

  return (
    <div className="grid">
      <label className="filter-bar">
        <span className="muted">Scénario</span>
        <select value={scenario} onChange={(event) => setScenario(event.target.value as Scenario)}>
          {Object.entries(SCENARIOS).map(([key, label]) => (
            <option key={key} value={key}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <ol className="steps">
        {steps.map((step) => (
          <li key={step.what}>
            <span className={`role role--${step.who === "Attaquant" ? "red" : "blue"}`}>{step.who}</span>
            <span>{step.what}</span>
            <code className="mono">{step.command}</code>
          </li>
        ))}
      </ol>
    </div>
  );
}
