export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state--error" role="alert">
      <p className="state__title">Impossible de charger les données ({message}).</p>
      {onRetry && (
        <button type="button" onClick={onRetry}>
          Réessayer
        </button>
      )}
    </div>
  );
}
