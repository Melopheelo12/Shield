import { useEffect, useState, type FormEvent } from "react";
import { login, LoginError } from "../api/auth";
import { Icon } from "../components/layout/icons";

/** Écran de connexion de l'exploitant (US-19). Un seul compte, défini sur le serveur. */
export function Login({ expired, onSuccess }: { expired: boolean; onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [waitUntil, setWaitUntil] = useState(0);
  const [now, setNow] = useState(() => Date.now());

  const remaining = Math.max(0, Math.ceil((waitUntil - now) / 1000));

  useEffect(() => {
    if (waitUntil <= Date.now()) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [waitUntil]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login(username, password);
      onSuccess();
    } catch (caught) {
      const failure = caught instanceof LoginError ? caught.failure : null;
      if (failure?.kind === "invalid") setError("Identifiant ou mot de passe incorrect.");
      else if (failure?.kind === "throttled") {
        setNow(Date.now());
        setWaitUntil(Date.now() + failure.retryAfter * 1000);
        setError(null);
      } else setError("Le collecteur ne répond pas. Réessayez dans un instant.");
      setPassword("");
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="login">
      <form className="login__card panel" onSubmit={submit} aria-labelledby="login-title">
        <p className="brand">
          <span className="brand__mark" aria-hidden="true">
            <Icon name="defense" size={20} />
          </span>
          SHIELD
        </p>
        <h1 id="login-title">Connexion</h1>
        {expired && <p className="muted">Votre session a expiré : reconnectez-vous.</p>}
        <label>
          Identifiant
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            maxLength={128}
            required
            autoFocus
          />
        </label>
        <label>
          Mot de passe
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            maxLength={256}
            required
          />
        </label>
        <p className="login__error" role="alert">
          {remaining > 0 ? `Trop d'essais : nouvel essai possible dans ${formatWait(remaining)}.` : error}
        </p>
        <button type="submit" disabled={pending || remaining > 0}>
          {pending ? "Connexion…" : "Se connecter"}
        </button>
      </form>
    </main>
  );
}

function formatWait(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest ? `${minutes} min ${rest} s` : `${minutes} min`;
}
