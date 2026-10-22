import { STATS, type CredentialItem, type TopCredentials as Credentials } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { formatAttackerText } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { BarList } from "./BarList";

function toBars(items: CredentialItem[]) {
  // Saisies d'attaquants : rendues comme texte, tronquées, jamais interprétées.
  return items.map((item) => ({
    key: item.value,
    label: (
      <span className="mono" title={item.value}>
        {formatAttackerText(item.value, 28)}
      </span>
    ),
    value: item.count,
  }));
}

/** Identifiants et mots de passe les plus essayés (US-24). */
export function TopCredentials({ limit = 8 }: { limit?: number }) {
  const stats = useApi<Credentials>(STATS.topCredentials(limit), 10_000);
  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;
  const data = stats.status === "ready" ? stats.data : { usernames: [], passwords: [] };
  if (data.usernames.length === 0 && data.passwords.length === 0) {
    return <EmptyState title="Aucun identifiant tenté pour l'instant." />;
  }

  return (
    <div className="grid grid--split">
      <div>
        <h3 className="panel__sub">Identifiants</h3>
        <BarList label="Identifiants les plus essayés" items={toBars(data.usernames)} />
      </div>
      <div>
        <h3 className="panel__sub">Mots de passe</h3>
        <BarList label="Mots de passe les plus essayés" items={toBars(data.passwords)} />
      </div>
    </div>
  );
}
