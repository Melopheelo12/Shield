import { useEffect, useRef, useState } from "react";
import { logout, streamUrl } from "../api/auth";
import type { NormalizedEvent } from "../types/events";
import { mergeFeed } from "../utils/feed";

/** Code de fermeture du collecteur pour un jeton absent ou invalide. */
const POLICY_VIOLATION = 1008;

/**
 * `connecting` : première connexion ; `open` : flux actif ; `reconnecting` : la
 * connexion vient de tomber ; `down` : une nouvelle tentative a échoué, le flux est
 * coupé (les essais continuent en arrière-plan).
 */
export type ConnectionState = "connecting" | "open" | "reconnecting" | "down";

type Frame = { type: "event"; data: NormalizedEvent } | { type: "ping" };

/**
 * Flux temps réel des événements (US-20).
 *
 * Deux exigences encodées ici :
 *  - la reconnexion est automatique, avec repli exponentiel plafonné ;
 *  - l'état de la connexion est TOUJOURS exposé : sans signal visible, l'utilisateur
 *    ne peut pas distinguer « calme » de « cassé ».
 *
 * Le jeton passe en paramètre `token` et il est relu à chaque reconnexion. Un refus
 * (code 1008) déconnecte au lieu de réessayer sans fin avec un jeton périmé.
 */
export function useWebSocket(path = "/ws/events", maxEvents = 50) {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryDelay = 1000;
    let timer: ReturnType<typeof setTimeout>;
    let disposed = false;
    let wasOpen = false;

    const connect = () => {
      if (disposed) return;
      socket = new WebSocket(streamUrl(path));

      socket.onopen = () => {
        retryDelay = 1000;
        wasOpen = true;
        setConnection("open");
      };

      socket.onmessage = (message) => {
        if (pausedRef.current) return;
        let frame: Frame;
        try {
          frame = JSON.parse(message.data as string) as Frame;
        } catch {
          return; // trame illisible : ignorée, le flux continue
        }
        if (frame.type !== "event") return; // « ping » : garde la connexion ouverte
        // Le flux est plafonné : une liste qui défile sans fin est illisible
        // et empêche de cliquer.
        setEvents((current) => mergeFeed([frame.data], current, maxEvents));
      };

      socket.onclose = (event) => {
        if (disposed) return;
        if (event.code === POLICY_VIOLATION) {
          logout();
          return;
        }
        setConnection(wasOpen ? "reconnecting" : "down");
        wasOpen = false;
        timer = setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 2, 30000);
      };
    };

    connect();
    return () => {
      disposed = true;
      clearTimeout(timer);
      socket?.close();
    };
  }, [path, maxEvents]);

  return { events, connection, paused, setPaused };
}
