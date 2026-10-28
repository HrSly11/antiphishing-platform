import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import KpiCard from '../../../src/components/dashboard/KpiCard';

describe('KpiCard component rendering', () => {
  it('renders KPI title, metric value, subtitle, and semantic accent color', () => {
    const html = renderToStaticMarkup(
      <KpiCard
        title="Malicious Quarantined"
        value="28"
        subtitle="Blocked inline at MTA gateway"
        accent="red"
      />,
    );

    expect(html).toContain('Malicious Quarantined');
    expect(html).toContain('28');
    expect(html).toContain('Blocked inline at MTA gateway');
    expect(html).toContain('text-red-600');
  });
});
