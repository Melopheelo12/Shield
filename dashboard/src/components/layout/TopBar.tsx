import { logout } from "../../api/auth";
import { ConnectionStatus } from "../common/ConnectionStatus";

export function TopBar({ title }: { title: string }) {
  return (
    <header className="topbar">
      <h1>{title}</h1>
      <div className="topbar__actions">
        <ConnectionStatus />
        <button type="button" onClick={() => logout("manual")}>
          Se déconnecter
        </button>
      </div>
    </header>
  );
}
