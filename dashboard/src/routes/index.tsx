import type { ReactNode } from "react";
import type { IconName } from "../components/layout/icons";
import { Attacks } from "../pages/Attacks";
import { Overview } from "../pages/Overview";
import { ThreatMap } from "../pages/ThreatMap";

export interface AppRoute {
  /** Fragment d'URL : `""` pour l'accueil, `"journal"` pour `#/journal`. */
  path: string;
  label: string;
  icon: IconName;
  render: () => ReactNode;
}

/** Ordre de la barre latérale : surveiller, localiser, comprendre, contrer, s'entraîner. */
export const ROUTES: AppRoute[] = [
  { path: "", label: "Vue d'ensemble", icon: "overview", render: () => <Overview /> },
  { path: "carte", label: "Carte des menaces", icon: "map", render: () => <ThreatMap /> },
  { path: "journal", label: "Journal des attaques", icon: "journal", render: () => <Attacks /> },
];

export function findRoute(path: string): AppRoute {
  return ROUTES.find((route) => route.path === path) ?? ROUTES[0];
}
