// Persistent top bar: identity, live health, and the primary "Run scan" action.

function HealthStatus({ health, error }) {
  if (error) {
    return (
      <div className="health" title={error}>
        <span className="dot dot-bad" aria-hidden="true" />
        <span className="health-text">health unavailable</span>
      </div>
    );
  }
  if (!health) {
    return (
      <div className="health">
        <span className="dot dot-idle" aria-hidden="true" />
        <span className="health-text">checking…</span>
      </div>
    );
  }
  const ok = health.status === 'ok';
  return (
    <div className="health">
      <span
        className={ok ? 'dot dot-ok' : 'dot dot-bad'}
        role="img"
        aria-label={ok ? 'Service healthy' : 'Service unhealthy'}
      />
      <span className="health-text">
        <span className="health-meta">v{health.version || '—'}</span>
        <span className="health-sep" aria-hidden="true">·</span>
        <span className="health-meta">{health.environment || '—'}</span>
      </span>
      {health.image_tag ? <span className="pill" title="Image tag">{health.image_tag}</span> : null}
    </div>
  );
}

export default function Header({ health, healthError, running, onRunScan }) {
  return (
    <header className="app-header">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">B0</span>
        <div className="brand-text">
          <h1 className="brand-title">Ba0Ba0 · Batch Worker</h1>
          <p className="brand-subtitle">Scanner-report ingestion</p>
        </div>
      </div>

      <div className="header-right">
        <HealthStatus health={health} error={healthError} />
        <button
          type="button"
          className="btn btn-primary"
          onClick={onRunScan}
          disabled={running}
          aria-busy={running}
        >
          {running ? (
            <>
              <span className="spinner" aria-hidden="true" />
              Running…
            </>
          ) : (
            'Run scan'
          )}
        </button>
      </div>
    </header>
  );
}
