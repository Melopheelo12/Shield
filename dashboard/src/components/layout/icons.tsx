/** Icônes en SVG embarqué : la CSP de nginx n'autorise aucune ressource externe. */
const PATHS = {
  overview: "M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z",
  map: "M9 3 3 5.5v15.5l6-2.5 6 2.5 6-2.5V3l-6 2.5zm0 2.2 6 2.5v11.1l-6-2.5z",
  journal: "M4 4h16v2H4zm0 5h16v2H4zm0 5h10v2H4zm0 5h10v2H4z",
  defense: "M12 2 4 5v6c0 5 3.4 9.6 8 11 4.6-1.4 8-6 8-11V5z",
  sandbox: "M7 2v2h1v5.6L3.3 18A2.6 2.6 0 0 0 5.6 22h12.8a2.6 2.6 0 0 0 2.3-4L16 9.6V4h1V2zm3 2h4v6.2l2.2 3.8H7.8L10 10.2z",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
      <path d={PATHS[name]} />
    </svg>
  );
}
