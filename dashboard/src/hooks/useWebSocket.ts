import { useEffect, useRef, useState } from "react";
import type { NormalizedEvent } from "../types/events";

export type ConnectionState = "connecting" | "open" | "closed";

/**
 * Flux temps réel des événements (US-20).
 *
 * Deux exigences encodées ici :
 *  - la reconnexion est automatique, avec repli exponentiel plafonné ;
 *  - l'état de la connexion est TOUJOURS exposé : sans signal visible, l'utilisateur
 *    ne peut pas distinguer « calme » de « cassé ».
 */
export function useWebSocket(url: string, maxEvents = 50) {
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

    const connect = () => {
      if (disposed) return;
      setConnection("connecting");
      socket = new WebSocket(url);

      socket.onopen = () => {
        retryDelay = 1000;
        setConnection("open");
      };

      socket.onmessage = (message) => {
        if (pausedRef.current) return;
        const frame = JSON.parse(message.data as string) as {
          type: string;
          data: NormalizedEvent;
        };
        if (frame.type !== "event") return;
        // Le flux est plafonné : une liste qui défile sans fin est illisible
        // et empêche de cliquer.
        setEvents((current) => [frame.data, ...current].slice(0, maxEvents));
      };

      socket.onclose = () => {
        setConnection("closed");
        if (disposed) return;
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
  }, [url, maxEvents]);

  return { events, connection, paused, setPaused };
}
