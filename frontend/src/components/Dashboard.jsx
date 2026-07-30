import { useEffect, useState } from 'react';
import StatCard from './StatCard.jsx';
import { getMetrics, getJobs } from '../api.js';
import { SEVERITIES, CHANNELS, channelLabel } from '../constants.js';

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatRatio(ratio) {
  const n = Number(ratio);
  if (!Number.isFinite(n)) return '—';
  return `${Math.round(n * 100)}%`;
}

function RunStatusBadge({ status }) {
  const value = (status || '').toLowerCase();
  const cls = ['succeeded', 'failed', 'running'].includes(value) ? value : 'unknown';
  return <span className={`badge badge-status status-${cls}`}>{status || 'unknown'}</span>;
}

export default function Dashboard({ refreshNonce }) {
  const [metrics, setMetrics] = useState(null);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    Promise.all([getMetrics(), getJobs(20)])
      .then(([m, j]) => {
        if (cancelled) return;
        setMetrics(m || {});
        setRuns(Array.isArray(j?.runs) ? j.runs : []);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load dashboard.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshNonce]);

  const bySeverity = metrics?.by_severity || {};
  const byChannel = metrics?.by_channel || {};
  const total = SEVERITIES.reduce((sum, s) => sum + (Number(bySeverity[s]) || 0), 0);
  const channelMax = Math.max(1, ...CHANNELS.map((c) => Number(byChannel[c]) || 0));

  const sortedRuns = [...runs].sort((a, b) => {
    const ta = new Date(a.started_at || 0).getTime();
    const tb = new Date(b.started_at || 0).getTime();
    return (Number.isNaN(tb) ? 0 : tb) - (Number.isNaN(ta) ? 0 : ta);
  });

  return (
    <div className="dashboard">
      {error ? (
        <div className="banner banner-error" role="alert">
          <strong>Couldn’t load dashboard.</strong> {error}
        </div>
      ) : null}

      <section aria-labelledby="sev-heading">
        <h2 id="sev-heading" className="section-title">
          Findings by severity
        </h2>
        <div className="stat-row">
          {SEVERITIES.map((sev) => (
            <StatCard
              key={sev}
              label={sev}
              tone={sev.toLowerCase()}
              value={loading && !metrics ? '—' : Number(bySeverity[sev]) || 0}
            />
          ))}
          <StatCard label="Total" tone="total" value={loading && !metrics ? '—' : total} />
        </div>
      </section>

      <div className="dash-grid">
        <section className="card" aria-labelledby="chan-heading">
          <h2 id="chan-heading" className="section-title">
            Remediation channels
          </h2>
          <ul className="channel-list">
            {CHANNELS.map((chan) => {
              const count = Number(byChannel[chan]) || 0;
              const pct = Math.round((count / channelMax) * 100);
              return (
                <li key={chan} className="channel-row">
                  <span className="channel-name">{channelLabel(chan)}</span>
                  <span className="channel-track" aria-hidden="true">
                    <span className="channel-fill" style={{ width: `${count ? Math.max(pct, 3) : 0}%` }} />
                  </span>
                  <span className="channel-count">{count}</span>
                </li>
              );
            })}
          </ul>
        </section>

        <section className="card" aria-labelledby="runs-heading">
          <h2 id="runs-heading" className="section-title">
            Recent runs
          </h2>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Started</th>
                  <th scope="col" className="num">Sources</th>
                  <th scope="col" className="num">Ingested</th>
                  <th scope="col" className="num">New</th>
                  <th scope="col" className="num">Mechanical</th>
                </tr>
              </thead>
              <tbody>
                {sortedRuns.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-cell">
                      {loading ? 'Loading runs…' : 'No runs yet — click “Run scan”.'}
                    </td>
                  </tr>
                ) : (
                  sortedRuns.map((run) => (
                    <tr key={run.id}>
                      <td><RunStatusBadge status={run.status} /></td>
                      <td className="nowrap">{formatDateTime(run.started_at)}</td>
                      <td className="num">{run.sources ?? 0}</td>
                      <td className="num">{run.findings_ingested ?? 0}</td>
                      <td className="num">{run.findings_new ?? 0}</td>
                      <td className="num">{formatRatio(run.mechanical_ratio)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
