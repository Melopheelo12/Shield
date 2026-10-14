import { AppShell } from "./components/layout/AppShell";
import { useAuth } from "./hooks/useAuth";
import { EventStreamProvider } from "./hooks/useEventStream";
import { useHashRoute } from "./hooks/useHashRoute";
import { Login } from "./pages/Login";
import { findRoute } from "./routes";

export function App() {
  const route = findRoute(useHashRoute());
  const auth = useAuth();
  if (!auth.authenticated) return <Login expired={auth.expired} onSuccess={auth.signedIn} />;
  return (
    <EventStreamProvider>
      <AppShell current={route.path} title={route.label}>
        {route.render()}
      </AppShell>
    </EventStreamProvider>
  );
}
