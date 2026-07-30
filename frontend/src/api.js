// Same-origin API client for the baobao-batch-worker backend.
//
// Every path is relative, so the browser hits whatever origin served the page:
// in production the Flask app itself (it serves this SPA), and in dev the Vite
// server which proxies these paths to http://localhost:8080 (see vite.config.js).

/** Thrown for any non-2xx response or transport failure. Carries an operator-facing message. */
export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(path, {
      headers: { Accept: 'application/json', ...(options.headers || {}) },
      ...options,
    });
  } catch (err) {
    // Network / DNS / connection-refused — fetch rejects before any response.
    throw new ApiError(`Network error contacting ${path}: ${err.message}`, 0);
  }

  let body = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    const detail = body && (body.detail || body.error);
    throw new ApiError(
      detail ? `${res.status} ${res.statusText}: ${detail}` : `${res.status} ${res.statusText}`,
      res.status,
    );
  }
  return body;
}

/** GET /healthz -> {status, service, version, image_tag, environment, time} */
export function getHealth() {
  return request('/healthz');
}

/** GET /metrics -> {by_severity, by_channel, by_repo, by_scanner} */
export function getMetrics() {
  return request('/metrics');
}

/** GET /api/jobs?limit=n -> {runs:[...]} */
export function getJobs(limit = 20) {
  return request(`/api/jobs?limit=${encodeURIComponent(limit)}`);
}

/** POST /api/jobs/run -> {run, by_severity, by_channel, reported, source_errors} */
export function runScan() {
  return request('/api/jobs/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
}

/**
 * GET /api/findings.
 *
 * The backend has two mutually-exclusive query paths: a free-text `search`, and a
 * structured filter (`severity`/`channel`/`repo`). If `search` is non-empty we send
 * ONLY search — the backend's search path ignores the filter params.
 */
export function getFindings({ search = '', severity = '', channel = '', repo = '', limit = 200 } = {}) {
  const params = new URLSearchParams();
  const trimmed = search.trim();
  if (trimmed) {
    params.set('search', trimmed);
  } else {
    if (severity) params.set('severity', severity);
    if (channel) params.set('channel', channel);
    if (repo) params.set('repo', repo);
  }
  params.set('limit', String(limit));
  return request(`/api/findings?${params.toString()}`);
}
