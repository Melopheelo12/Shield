import { useMemo, useState } from "react";
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { STATS, type TimelineResponse } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { fillTimeline, PERIODS, type PeriodKey } from "../../utils/timeline";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

function tickFormat(stepMs: number) {
  const options: Intl.DateTimeFormatOptions =
    stepMs >= 86_400_000 ? { day: "2-digit", month: "2-digit" } : { hour: "2-digit", minute: "2-digit" };
  const format = new Intl.DateTimeFormat("fr-FR", options);
  return (value: number) => format.format(value);
}

/**
 * Chronologie des tentatives et de la menace maximale (US-22), calculée par le
 * collecteur sur tout l'historique de la période — pas sur un échantillon.
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
  const total = slots.reduce((sum, slot) => sum + slot.events, 0);

  const picker = (
    <div className="segmented" role="group" aria-label="Période">
      {PERIODS.map((item) => (
        <button
          key={item.key}
          type="button"
          aria-pressed={item.key === periodKey}
          onClick={() => setPeriodKey(item.key)}
        >
          {item.label}
        </button>
      ))}
    </div>
  );

  if (timeline.status === "loading") return <LoadingState />;
  if (timeline.status === "error") return <ErrorState message={timeline.message} onRetry={timeline.reload} />;

  const format = tickFormat(stepMs);
  const label = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" });

  return (
    <div className="chart">
      <div className="chart__toolbar">
        <span className="muted">
          {total.toLocaleString("fr-FR")} tentative{total > 1 ? "s" : ""} sur {period.label}
        </span>
        {picker}
      </div>
      <div role="img" aria-label={`Chronologie : ${total} tentatives sur ${period.label}`}>
        <ResponsiveContainer width="100%" height={240}>
          <ComposedChart data={slots} margin={{ top: 8, right: 0, bottom: 0, left: -16 }}>
            <CartesianGrid stroke="var(--border)" vertical={false} />
            <XAxis
              dataKey="start"
              type="number"
              scale="time"
              domain={["dataMin", "dataMax"]}
              tickFormatter={format}
              stroke="var(--muted)"
              fontSize={12}
            />
            <YAxis yAxisId="events" allowDecimals={false} stroke="var(--muted)" fontSize={12} />
            <YAxis yAxisId="score" orientation="right" domain={[0, 100]} stroke="var(--muted)" fontSize={12} />
            <Tooltip
              labelFormatter={(value: number) => label.format(value)}
              contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8 }}
            />
            <Area
              yAxisId="events"
              type="monotone"
              dataKey="events"
              name="Tentatives"
              stroke="var(--accent)"
              fill="var(--accent)"
              fillOpacity={0.2}
              isAnimationActive={false}
            />
            <Line
              yAxisId="score"
              type="stepAfter"
              dataKey="maxScore"
              name="Menace max."
              stroke="var(--sev-critical)"
              dot={false}
              isAnimationActive={false}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
