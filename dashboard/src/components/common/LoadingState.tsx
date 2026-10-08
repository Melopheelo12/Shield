export function LoadingState({ label = "Chargement…" }: { label?: string }) {
  return (
    <p className="state state--loading" role="status" aria-live="polite">
      {label}
    </p>
  );
}
