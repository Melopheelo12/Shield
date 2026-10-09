import { AppShell } from "./components/layout/AppShell";
import { useHashRoute } from "./hooks/useHashRoute";
import { findRoute } from "./routes";

export function App() {
  const route = findRoute(useHashRoute());
  return (
    <AppShell current={route.path} title={route.label}>
      {route.render()}
    </AppShell>
  );
}
