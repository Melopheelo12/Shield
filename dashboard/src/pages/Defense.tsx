import { Blocklist } from "../components/defense/Blocklist";
import { DetectionRules } from "../components/defense/DetectionRules";
import { EmergencyStop } from "../components/defense/EmergencyStop";

/** Contrer : bloquer les sources les plus dangereuses, connaître les règles, savoir couper. */
export function Defense() {
  return (
    <>
      <section className="panel" aria-labelledby="blocklist-title">
        <div className="panel__head">
          <h2 id="blocklist-title">Liste de blocage</h2>
          <span className="panel__hint">à relire avant de l'appliquer sur vos pare-feux</span>
        </div>
        <Blocklist />
      </section>

      <div className="grid grid--2">
        <section className="panel" aria-labelledby="rules-title">
          <div className="panel__head">
            <h2 id="rules-title">Règles de détection</h2>
            <span className="panel__hint">rules/detection_rules.yaml</span>
          </div>
          <DetectionRules />
        </section>

        <section className="panel" aria-labelledby="stop-title">
          <div className="panel__head">
            <h2 id="stop-title">Arrêt d'urgence</h2>
          </div>
          <EmergencyStop />
        </section>
      </div>
    </>
  );
}
