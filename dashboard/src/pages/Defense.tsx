import { AlertHistory } from "../components/defense/AlertHistory";
import { AlertThresholds } from "../components/defense/AlertThresholds";
import { Blocklist } from "../components/defense/Blocklist";
import { DetectionRules } from "../components/defense/DetectionRules";
import { EmergencyStop } from "../components/defense/EmergencyStop";
import { ExportPanel } from "../components/defense/ExportPanel";

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

      <section className="panel" aria-labelledby="alerts-title">
        <div className="panel__head">
          <h2 id="alerts-title">Seuils d'alerte</h2>
          <span className="panel__hint">enregistrés par le collecteur</span>
        </div>
        <AlertThresholds />
      </section>

      <section className="panel" aria-labelledby="history-title">
        <div className="panel__head">
          <h2 id="history-title">Alertes déclenchées</h2>
        </div>
        <AlertHistory />
      </section>

      <section className="panel" aria-labelledby="export-title">
        <div className="panel__head">
          <h2 id="export-title">Export des événements</h2>
          <span className="panel__hint">pour une analyse hors ligne</span>
        </div>
        <ExportPanel />
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
