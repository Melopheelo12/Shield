import { ConnectionStatus } from "../common/ConnectionStatus";

export function TopBar({ title }: { title: string }) {
  return (
    <header className="topbar">
      <h1>{title}</h1>
      <ConnectionStatus />
    </header>
  );
}
