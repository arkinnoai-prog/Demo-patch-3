import { useEffect } from 'react';

// Transient status message for the "Run scan" result. `kind` is 'success' | 'error'.
// Auto-dismisses; also dismissable. Uses role=status so screen readers announce it.

export default function Toast({ toast, onDismiss }) {
  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(onDismiss, 6000);
    return () => clearTimeout(t);
  }, [toast, onDismiss]);

  if (!toast) return null;

  return (
    <div className={`toast toast-${toast.kind}`} role="status" aria-live="polite">
      <span className="toast-msg">{toast.message}</span>
      <button type="button" className="toast-close" onClick={onDismiss} aria-label="Dismiss message">
        ×
      </button>
    </div>
  );
}
