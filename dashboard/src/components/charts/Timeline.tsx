import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useApi } from "../../hooks/useApi";
import type { NormalizedEvent, ServiceName } from "../../types/events";
import { bucketize } from "../../utils/timeline";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

const SERVICES: ServiceName[] = ["ssh", "http", "ftp"];
const SAMPLE = 500;

function tickFormat(step: number) {
  const options: Intl.DateTimeFormatOptions =
    step >= 86_400_000 ? { day: "2-digit", month: "2-digit" } : { hour: "2-digit", minute: "2-digit" };
  const format = new Intl.DateTimeFormat("fr-FR", options);
  return (value: number) => format.format(value);
}

/** Chronologie des tentatives, empilée par service (US-22). */
export function Timeline() {
  const events = useApi<{ items: NormalizedEvent[] }>(`/api/v1/events?limit=${SAMPLE}`, 10_000);
  const items = events.status === "ready" ? events.data.items : null;
  const { step, buckets } = useMemo(() => bucketize(items ?? []), [items]);

  if (events.status === "loading") return <LoadingState />;
  if (events.status === "error") return <ErrorState message={events.message} onRetry={events.reload} />;
  if (buckets.length === 0) return <EmptyState title="Pas encore de données à tracer." />;

  const format = tickFormat(step);
  const label = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" });

  return (
    <div className="chart" role="img" aria-label={`Chronologie des ${items?.length ?? 0} dernières tentatives`}>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={buckets} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
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
          <YAxis allowDecimals={false} stroke="var(--muted)" fontSize={12} />
          <Tooltip
            labelFormatter={(value: number) => label.format(value)}
            contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8 }}
          />
          {SERVICES.map((service) => (
            <Area
              key={service}
              type="monotone"
              dataKey={service}
              name={service.toUpperCase()}
              stackId="services"
              stroke={`var(--svc-${service})`}
              fill={`var(--svc-${service})`}
              fillOpacity={0.25}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
