import { ROUTES } from "../../routes";
import { Icon } from "./icons";

export function Sidebar({ current }: { current: string }) {
  return (
    <nav className="sidebar" aria-label="Navigation principale">
      <a className="brand" href="#/">
        <span className="brand__mark" aria-hidden="true">
          <Icon name="defense" size={20} />
        </span>
        SHIELD
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
    </nav>
  );
}
