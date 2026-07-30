import { useEffect, useState } from 'react';
import SeverityBadge from './SeverityBadge.jsx';
import { getFindings } from '../api.js';
import { SEVERITIES, CHANNELS, channelLabel } from '../constants.js';

function VulnLink({ finding }) {
  const label = finding.vuln_id || '—';
  if (finding.primary_url) {
    return (
      <a className="link" href={finding.primary_url} target="_blank" rel="noopener noreferrer">
        {label}
        <span className="ext" aria-hidden="true"> ↗</span>
      </a>
    );
  }
  return <span>{label}</span>;
}

function VersionCell({ finding }) {
  const from = finding.installed_version || '—';
  const to = finding.fixed_version;
  return (
    <span className="versions">
      <code className="ver-from">{from}</code>
      {to ? (
        <>
          <span className="ver-arrow" aria-hidden="true"> → </span>
          <code className="ver-to">{to}</code>
        </>
      ) : (
        <span className="ver-none"> → not fixed</span>
      )}
    </span>
  );
}

export default function Findings({ refreshNonce }) {
  const [searchInput, setSearchInput] = useState('');
  // The committed query. Search and filters are mutually exclusive per the backend
  // contract: a non-empty `search` ignores severity/channel, so submitting a search
  // clears the filters and changing a filter clears the search.
  const [query, setQuery] = useState({ search: '', severity: '', channel: '' });
  const [findings, setFindings] = useState([]);
  const [count, setCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    getFindings(query)
      .then((res) => {
        if (cancelled) return;
        setFindings(Array.isArray(res?.findings) ? res.findings : []);
        setCount(typeof res?.count === 'number' ? res.count : res?.findings?.length || 0);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message || 'Failed to load findings.');
        setFindings([]);
        setCount(0);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [query, refreshNonce]);

  function submitSearch(e) {
    e.preventDefault();
    setQuery({ search: searchInput.trim(), severity: '', channel: '' });
  }

  function onSeverityChange(value) {
    setSearchInput('');
    setQuery((q) => ({ search: '', severity: value, channel: q.channel }));
  }

  function onChannelChange(value) {
    setSearchInput('');
    setQuery((q) => ({ search: '', severity: q.severity, channel: value }));
  }

  const hasQuery = Boolean(query.search || query.severity || query.channel);

  return (
    <div className="findings">
      <div className="findings-controls card">
        <form className="search-form" role="search" onSubmit={submitSearch}>
          <label className="field grow">
            <span className="field-label">Search</span>
            <input
              type="search"
              className="input"
              placeholder="Search findings by title or package…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </label>
          <button type="submit" className="btn btn-secondary">Search</button>
        </form>

        <div className="filters">
          <label className="field">
            <span className="field-label">Severity</span>
            <select
              className="input"
              value={query.severity}
              onChange={(e) => onSeverityChange(e.target.value)}
            >
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>

          <label className="field">
            <span className="field-label">Channel</span>
            <select
              className="input"
              value={query.channel}
              onChange={(e) => onChannelChange(e.target.value)}
            >
              <option value="">All channels</option>
              {CHANNELS.map((c) => (
                <option key={c} value={c}>{channelLabel(c)}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {error ? (
        <div className="banner banner-error" role="alert">
          <strong>Couldn’t load findings.</strong> {error}
        </div>
      ) : null}

      <div className="findings-meta">
        <span className="count" aria-live="polite">
          {loading ? 'Loading…' : `${count} finding${count === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="card table-card">
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Vuln ID</th>
                <th scope="col">Package</th>
                <th scope="col">Installed → Fixed</th>
                <th scope="col">Channel</th>
                <th scope="col">Title</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="empty-cell">Loading findings…</td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty-cell">
                    {hasQuery ? 'No findings match your search or filters.' : 'No findings — run a scan.'}
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td><VulnLink finding={f} /></td>
                    <td className="nowrap"><code>{f.package_name || '—'}</code></td>
                    <td><VersionCell finding={f} /></td>
                    <td className="nowrap">{channelLabel(f.remediation_channel)}</td>
                    <td className="title-cell">{f.title || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
