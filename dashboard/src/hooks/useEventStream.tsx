import { createContext, useContext, type ReactNode } from "react";
import type { NormalizedEvent } from "../types/events";
import { useWebSocket, type ConnectionState } from "./useWebSocket";

interface EventStream {
  events: NormalizedEvent[];
  connection: ConnectionState;
}

const EventStreamContext = createContext<EventStream>({ events: [], connection: "connecting" });

/**
 * Une seule connexion WebSocket pour toute l'application : la barre du haut en montre
 * l'état sur chaque page, le flux en direct en affiche les trames.
 */
export function EventStreamProvider({ children }: { children: ReactNode }) {
  const { events, connection } = useWebSocket("/ws/events", 50);
  return <EventStreamContext.Provider value={{ events, connection }}>{children}</EventStreamContext.Provider>;
}

export function useEventStream(): EventStream {
  return useContext(EventStreamContext);
}
