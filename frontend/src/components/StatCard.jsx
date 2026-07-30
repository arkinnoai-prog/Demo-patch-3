// A single KPI tile: a big count with a labelled accent. Used for the per-severity
// row and the Total. `tone` selects the accent (sev-* class or 'total').

export default function StatCard({ label, value, tone = 'total' }) {
  return (
    <div className={`stat-card tone-${tone}`}>
      <span className="stat-accent" aria-hidden="true" />
      <div className="stat-body">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
