import { IsolationBanner } from "../components/sandbox/IsolationBanner";
import { SandboxControls } from "../components/sandbox/SandboxControls";
import { TrainingReport } from "../components/sandbox/TrainingReport";

/** S'entraîner : un membre attaque, l'autre défend, et la grille mesure l'agent. */
export function Sandbox() {
  return (
    <>
      <IsolationBanner />
      <div className="grid grid--2">
        <section className="panel" aria-labelledby="run-title">
          <div className="panel__head">
            <h2 id="run-title">Déroulé d'une partie</h2>
          </div>
          <SandboxControls />
        </section>
        <section className="panel" aria-labelledby="report-title">
          <div className="panel__head">
            <h2 id="report-title">Grille de partie</h2>
            <span className="panel__hint">enregistrée dans ce navigateur</span>
          </div>
          <TrainingReport />
        </section>
      </div>
    </>
  );
}
