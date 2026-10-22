import { useMemo, useState } from "react";
import { STATS, type TimelineResponse } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { fillTimeline, PERIODS, type PeriodKey, type TimelineSlot } from "../../utils/timeline";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { threatLevel } from "../common/ThreatScore";

const number = new Intl.NumberFormat("fr-FR");

function slotLabel(stepMs: number) {
  const options: Intl.DateTimeFormatOptions =
    stepMs >= 86_400_000 ? { day: "2-digit", month: "2-digit" } : { hour: "2-digit", minute: "2-digit" };
  const format = new Intl.DateTimeFormat("fr-FR", options);
  return (slot: TimelineSlot) => format.format(slot.start);
}

/**
 * Activité par tranche (US-22), calculée par le collecteur sur tout l'historique de la
 * période. Barres en CSS : chaque barre porte son libellé, lu par un lecteur d'écran.
 */
export function Timeline() {
  const [periodKey, setPeriodKey] = useState<PeriodKey>("24h");
  const period = PERIODS.find((item) => item.key === periodKey) ?? PERIODS[1];
  const timeline = useApi<TimelineResponse>(STATS.timeline(period.hours, period.bucketMinutes), 30_000);
  const data = timeline.status === "ready" ? timeline.data : null;
  const stepMs = period.bucketMinutes * 60_000;
  const slots = useMemo(
    () => (data ? fillTimeline(data.items, Date.parse(data.since), stepMs, Date.now()) : []),
    [data, stepMs],
  );

  if (timeline.status === "loading") return <LoadingState />;
  if (timeline.status === "error") return <ErrorState message={timeline.message} onRetry={timeline.reload} />;

  const total = slots.reduce((sum, slot) => sum + slot.events, 0);
  const peak = slots.reduce<TimelineSlot | null>((best, slot) => (!best || slot.events > best.events ? slot : best), null);
  const max = Math.max(1, peak?.events ?? 0);
  const label = slotLabel(stepMs);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((ratio) => slots[Math.min(slots.length - 1, Math.round(ratio * (slots.length - 1)))]);

  return (
    <div className="activity">
      <div className="chart__toolbar">
        <span className="muted">
          {total === 0 || !peak
            ? `Aucune tentative sur ${period.label}`
            : `${number.format(total)} tentatives sur ${period.label} · pic à ${label(peak)} (${number.format(peak.events)})`}
        </span>
        <div className="segmented" role="group" aria-label="Période">
          {PERIODS.map((item) => (
            <button key={item.key} type="button" aria-pressed={item.key === periodKey} onClick={() => setPeriodKey(item.key)}>
              {item.label}
            </button>
          ))}
        </div>
      </div>
      <div className="activity__plot">
        <div className="activity__axis" aria-hidden="true">
          {[1, 2 / 3, 1 / 3, 0].map((ratio) => (
            <span key={ratio}>{number.format(Math.round(max * ratio))}</span>
          ))}
        </div>
        <div className="activity__body">
          <ol className="activity__bars" aria-label={`Tentatives par tranche sur ${period.label}`}>
            {slots.map((slot) => (
              <li
                key={slot.start}
                className={`activity__bar activity__bar--${threatLevel(slot.maxScore)}`}
                style={{ height: `${(slot.events / max) * 100}%` }}
                title={`${label(slot)} : ${slot.events} tentative(s), menace max ${slot.maxScore}`}
              >
                <span className="visually-hidden">
                  {label(slot)} : {slot.events} tentative(s)
                </span>
              </li>
            ))}
          </ol>
          <div className="activity__ticks" aria-hidden="true">
            {ticks.map((slot, index) => slot && <span key={index}>{label(slot)}</span>)}
          </div>
        </div>
      </div>
    </div>
  );
}
