import { useEffect, useState } from "react";
import { getToken, LOGOUT_EVENT, type LogoutReason } from "../api/auth";

/**
 * État de connexion du tableau de bord. Il bascule sur l'écran de connexion dès qu'un
 * appel reçoit un 401 ou que l'exploitant se déconnecte (événement `shield:logout`).
 */
export function useAuth() {
  const [authenticated, setAuthenticated] = useState(() => getToken() !== null);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    const onLogout = (event: Event) => {
      const reason = (event as CustomEvent<LogoutReason>).detail;
      setExpired(reason === "expired");
      setAuthenticated(false);
    };
    window.addEventListener(LOGOUT_EVENT, onLogout);
    return () => window.removeEventListener(LOGOUT_EVENT, onLogout);
  }, []);

  const signedIn = () => {
    setExpired(false);
    setAuthenticated(true);
  };

  return { authenticated, expired, signedIn };
}
