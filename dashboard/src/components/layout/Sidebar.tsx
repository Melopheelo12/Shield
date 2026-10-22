import { ROUTES } from "../../routes";
import { Icon } from "./icons";

export function Sidebar({ current }: { current: string }) {
  return (
    <nav className="sidebar" aria-label="Navigation principale">
      <a className="brand" href="#/">
        <span className="brand__mark" aria-hidden="true">
          <Icon name="defense" size={26} />
        </span>
        <span className="brand__name">
          SHIELD
          <small>Honeypot</small>
        </span>
      </a>
      <ul>
        {ROUTES.map((route) => (
          <li key={route.path}>
            <a
              href={`#/${route.path}`}
              className="sidebar__link"
              aria-current={route.path === current ? "page" : undefined}
            >
              <Icon name={route.icon} />
              <span>{route.label}</span>
            </a>
          </li>
        ))}
      </ul>
      {/* Un lien, pas un bouton : l'arrêt se fait sur le serveur (US-48), la page Défense
          en donne la procédure. Aucune action destructive ne part du navigateur. */}
      <a className="sidebar__emergency" href="#/defense">
        <Icon name="power" size={16} />
        Arrêt d'urgence
      </a>
    </nav>
  );
}
