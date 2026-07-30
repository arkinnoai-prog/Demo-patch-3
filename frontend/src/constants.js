// Domain vocabulary, kept in one place so the dashboard, badges and filters agree.

// Ordered low->high so stat cards and dropdowns read consistently.
export const SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export const CHANNELS = [
  'base_image_bump',
  'os_package',
  'dependency_bump',
  'iac_fix',
  'ai_code_fix',
  'none',
];

// Human-friendly channel labels for display (values stay machine form for the API).
export const CHANNEL_LABELS = {
  base_image_bump: 'Base image bump',
  os_package: 'OS package',
  dependency_bump: 'Dependency bump',
  iac_fix: 'IaC fix',
  ai_code_fix: 'AI code fix',
  none: 'None',
};

export function channelLabel(value) {
  if (!value) return '—';
  return CHANNEL_LABELS[value] || value;
}
