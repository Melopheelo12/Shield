import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AppShell({
  current,
  title,
  children,
}: {
  current: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="shell">
      <Sidebar current={current} />
      <div className="shell__main">
        <TopBar title={title} />
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
