// A small pill showing a severity. Colour is an accent, but the text label always
// carries the meaning too — never colour alone — so it stays readable for CVD users.

export default function SeverityBadge({ severity }) {
  const value = (severity || 'UNKNOWN').toUpperCase();
  const known = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(value);
  const cls = known ? value.toLowerCase() : 'unknown';
  return <span className={`badge badge-sev sev-${cls}`}>{value}</span>;
}
