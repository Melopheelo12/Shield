import { Attacks } from "./pages/Attacks";
import { Overview } from "./pages/Overview";

/**
 * Assemblage provisoire des vues, en attendant le routage et le shell
 * (`components/layout`). Vue d'ensemble puis journal des attaques.
 */
export function App() {
  return (
    <>
      <Overview />
      <Attacks />
    </>
  );
}
