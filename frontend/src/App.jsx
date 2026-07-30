import { useCallback, useEffect, useState } from 'react';
import Header from './components/Header.jsx';
import Dashboard from './components/Dashboard.jsx';
import Findings from './components/Findings.jsx';
import Toast from './components/Toast.jsx';
import { getHealth, runScan } from './api.js';

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'findings', label: 'Findings' },
];

export default function App() {
  const [tab, setTab] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState('');
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState(null);
  // Bumped after a scan so both tabs refetch their data.
  const [refreshNonce, setRefreshNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch((err) => {
        if (!cancelled) setHealthError(err.message || 'Health check failed.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleRunScan = useCallback(async () => {
    setRunning(true);
    setToast(null);
    try {
      const result = await runScan();
      const run = result?.run || {};
      const ingested = Number(run.findings_ingested) || 0;
      const fresh = Number(run.findings_new) || 0;
      const errors = Array.isArray(result?.source_errors) ? result.source_errors : [];
      let message = `${ingested} finding${ingested === 1 ? '' : 's'} (${fresh} new)`;
      if (errors.length) {
        message += ` — ${errors.length} source error${errors.length === 1 ? '' : 's'}`;
      }
      const failed = run.status === 'failed' || errors.length > 0;
      setToast({ kind: failed ? 'error' : 'success', message });
      // Refresh dashboard + findings, and re-check health.
      setRefreshNonce((n) => n + 1);
      getHealth()
        .then((h) => setHealth(h))
        .catch(() => {});
    } catch (err) {
      setToast({ kind: 'error', message: `Scan failed: ${err.message || 'unknown error'}` });
    } finally {
      setRunning(false);
    }
  }, []);

  return (
    <div className="app">
      <Header health={health} healthError={healthError} running={running} onRunScan={handleRunScan} />

      <nav className="tabs" aria-label="Views">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`tab ${tab === t.id ? 'tab-active' : ''}`}
            aria-current={tab === t.id ? 'page' : undefined}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {tab === 'dashboard' ? (
          <Dashboard refreshNonce={refreshNonce} />
        ) : (
          <Findings refreshNonce={refreshNonce} />
        )}
      </main>

      <Toast toast={toast} onDismiss={() => setToast(null)} />
    </div>
  );
}
