import { useCallback, useEffect, useState } from 'react';
import {
  Info,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import { formatUtcDateTime } from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type {
  IocFuzzySearchResponse,
  IocItem,
  IocPage,
  IocUpsertPayload,
} from '../types/domain';

type ListTab = 'ALL' | 'BLACKLIST' | 'WHITELIST';

export default function IocsPage() {
  const [listTab, setListTab] = useState<ListTab>('ALL');
  const [iocTypeFilter, setIocTypeFilter] = useState('');
  const [activeOnly, setActiveOnly] = useState(true);

  // pg_trgm Fuzzy Search state
  const [fuzzyMode, setFuzzyMode] = useState(false);
  const [fuzzyQuery, setFuzzyQuery] = useState('');
  const [fuzzyThreshold, setFuzzyThreshold] = useState(0.25);

  const [items, setItems] = useState<IocItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);

  // Upsert form
  const [form, setForm] = useState<IocUpsertPayload>({
    ioc_type: 'DOMAIN',
    ioc_value: '',
    list_type: 'BLACKLIST',
    confidence_score: 95,
    ttl_hours: 720,
    reason: 'SOC Analyst Threat Intelligence Block',
  });
  const [submitting, setSubmitting] = useState(false);

  const loadIocs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (fuzzyMode && fuzzyQuery.trim().length >= 2) {
        const res = await apiClient.get<IocFuzzySearchResponse>('/iocs/search', {
          params: { q: fuzzyQuery.trim(), threshold: fuzzyThreshold, limit: 40 },
        });
        const filtered =
          listTab === 'ALL'
            ? res.data.items
            : res.data.items.filter((i) => i.list_type === listTab);
        setItems(filtered);
        setTotal(filtered.length);
      } else {
        const params: Record<string, string | number | boolean> = {
          page: 1,
          page_size: 100,
          active_only: activeOnly,
        };
        if (listTab !== 'ALL') params.list_type = listTab;
        if (iocTypeFilter) params.ioc_type = iocTypeFilter;
        if (!fuzzyMode && fuzzyQuery.trim()) params.q = fuzzyQuery.trim();

        const res = await apiClient.get<IocPage>('/iocs', { params });
        setItems(res.data.items);
        setTotal(res.data.total);
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [fuzzyMode, fuzzyQuery, fuzzyThreshold, listTab, iocTypeFilter, activeOnly]);

  useEffect(() => {
    void loadIocs();
  }, [loadIocs]);

  const handleUpsert = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setBanner(null);
    try {
      const res = await apiClient.post<IocItem & { created: boolean }>('/iocs', form);
      setBanner(
        `${res.data.created ? 'Created' : 'Updated'} ${res.data.list_type} indicator '${res.data.ioc_value}'.`,
      );
      setForm({ ...form, ioc_value: '' });
      await loadIocs();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeactivate = async (id: string, value: string) => {
    setError(null);
    try {
      await apiClient.delete(`/iocs/${id}`);
      setBanner(`Deactivated indicator '${value}' (preserved in audit trail).`);
      await loadIocs();
    } catch (err) {
      setError(extractApiError(err));
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.IOCS_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
              <Shield className="w-3.5 h-3.5" />
              DYNAMIC BLACKLIST / WHITELIST &amp; PG_TRGM TRIGRAM INDEX
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Indicators of Compromise (IOC) Lists
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Manage institutional domains, URLs, IPs, emails, and SHA-256 hashes enforced inline by the detection gateway.
            </p>
          </div>

          <button type="button" onClick={() => void loadIocs()} className="soc-btn-secondary">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh IOCs
          </button>
        </div>

        {/* Precedence Governance Notice */}
        <div className="soc-card-muted p-3.5 flex items-center gap-2.5 text-xs text-slate-700 dark:text-slate-300 border-blue-500/30">
          <Info className="w-4 h-4 text-blue-500 shrink-0" />
          <span>
            <strong>Policy Precedence Rule:</strong> Verified <code>WHITELIST</code> entries take strict precedence over <code>BLACKLIST</code> and heuristic scores when SPF/DKIM/DMARC authentication passes (preventing disruption to official <code>bancocentral.com</code> rails).
          </span>
        </div>

        {banner && (
          <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-700 dark:text-emerald-300">
            {banner}
          </div>
        )}
        {error && (
          <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left: Upsert IOC Form */}
          <form onSubmit={handleUpsert} className="lg:col-span-4 soc-card p-5 space-y-3 text-xs">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">
              Create / Upsert Indicator
            </h2>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="soc-label mb-1">List Policy</label>
                <select
                  value={form.list_type}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      list_type: e.target.value as 'BLACKLIST' | 'WHITELIST',
                    })
                  }
                  className="soc-input font-mono"
                >
                  <option value="BLACKLIST">BLACKLIST</option>
                  <option value="WHITELIST">WHITELIST</option>
                </select>
              </div>
              <div>
                <label className="soc-label mb-1">IOC Type</label>
                <select
                  value={form.ioc_type}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      ioc_type: e.target.value as IocUpsertPayload['ioc_type'],
                    })
                  }
                  className="soc-input font-mono"
                >
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="URL">URL</option>
                  <option value="IP">IP</option>
                  <option value="EMAIL">EMAIL</option>
                  <option value="HASH">HASH (SHA-256)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="soc-label mb-1">Indicator Value</label>
              <input
                type="text"
                required
                minLength={3}
                placeholder="e.g. login-bancocentral-token.net"
                value={form.ioc_value}
                onChange={(e) => setForm({ ...form, ioc_value: e.target.value })}
                className="soc-input font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="soc-label mb-1">Confidence (0–100)</label>
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={form.confidence_score}
                  onChange={(e) =>
                    setForm({ ...form, confidence_score: Number(e.target.value) })
                  }
                  className="soc-input font-mono"
                />
              </div>
              <div>
                <label className="soc-label mb-1">TTL (Hours)</label>
                <input
                  type="number"
                  min={1}
                  max={87600}
                  value={form.ttl_hours ?? 720}
                  onChange={(e) => setForm({ ...form, ttl_hours: Number(e.target.value) })}
                  className="soc-input font-mono"
                />
              </div>
            </div>

            <div>
              <label className="soc-label mb-1">Source / Justification</label>
              <input
                type="text"
                required
                value={form.reason ?? ''}
                onChange={(e) => setForm({ ...form, reason: e.target.value })}
                className="soc-input"
              />
            </div>

            <RequirePermission permission={PERMISSIONS.IOCS_WRITE} mode="disable">
              <button type="submit" disabled={submitting} className="soc-btn-primary w-full">
                <Plus className="w-4 h-4" />
                {submitting ? 'Saving IOC...' : `Upsert to ${form.list_type}`}
              </button>
            </RequirePermission>
          </form>

          {/* Right: Tabs + pg_trgm Search + IOC Table */}
          <div className="lg:col-span-8 space-y-4">
            <div className="soc-card p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 p-1">
                  {(['ALL', 'BLACKLIST', 'WHITELIST'] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setListTab(t)}
                      className={`px-3 py-1 rounded-md text-xs font-mono font-bold transition ${
                        listTab === t
                          ? 'bg-blue-600 text-white'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => setFuzzyMode((v) => !v)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border inline-flex items-center gap-1.5 transition ${
                    fuzzyMode
                      ? 'bg-purple-600 text-white border-purple-500'
                      : 'soc-card text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  pg_trgm Fuzzy Mode: {fuzzyMode ? 'ON' : 'OFF'}
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div className="sm:col-span-2 relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder={
                      fuzzyMode
                        ? 'Type lookalike domain (e.g. bancocentrl) for pg_trgm similarity...'
                        : 'Filter indicators by substring...'
                    }
                    value={fuzzyQuery}
                    onChange={(e) => setFuzzyQuery(e.target.value)}
                    className="soc-input pl-8 font-mono"
                  />
                </div>

                {fuzzyMode ? (
                  <div>
                    <select
                      value={String(fuzzyThreshold)}
                      onChange={(e) => setFuzzyThreshold(Number(e.target.value))}
                      className="soc-input font-mono"
                    >
                      <option value="0.15">Threshold ≥ 0.15</option>
                      <option value="0.25">Threshold ≥ 0.25</option>
                      <option value="0.4">Threshold ≥ 0.40</option>
                    </select>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <select
                      value={iocTypeFilter}
                      onChange={(e) => setIocTypeFilter(e.target.value)}
                      className="soc-input font-mono"
                    >
                      <option value="">All Types</option>
                      <option value="DOMAIN">DOMAIN</option>
                      <option value="URL">URL</option>
                      <option value="IP">IP</option>
                      <option value="EMAIL">EMAIL</option>
                      <option value="HASH">HASH</option>
                    </select>
                    <label className="inline-flex items-center gap-1 text-[11px] shrink-0 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={activeOnly}
                        onChange={(e) => setActiveOnly(e.target.checked)}
                      />
                      Active
                    </label>
                  </div>
                )}
              </div>
            </div>

            <div className="soc-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                      <th className="p-3">List / Type</th>
                      <th className="p-3">Indicator Value</th>
                      <th className="p-3">Conf / Source</th>
                      {fuzzyMode && <th className="p-3">pg_trgm Sim</th>}
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                    {loading ? (
                      <tr>
                        <td colSpan={fuzzyMode ? 5 : 4} className="p-8 text-center text-slate-500">
                          Loading indicators...
                        </td>
                      </tr>
                    ) : items.length === 0 ? (
                      <tr>
                        <td colSpan={fuzzyMode ? 5 : 4} className="p-8 text-center text-slate-500">
                          No matching indicators found.
                        </td>
                      </tr>
                    ) : (
                      items.map((item) => (
                        <tr
                          key={item.id}
                          className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition"
                        >
                          <td className="p-3">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                                  item.list_type === 'WHITELIST'
                                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                                    : 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30'
                                }`}
                              >
                                {item.list_type}
                              </span>
                              <span className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-slate-200 dark:bg-slate-800">
                                {item.ioc_type}
                              </span>
                            </div>
                          </td>
                          <td className="p-3 max-w-xs">
                            <div className="font-mono font-semibold text-slate-900 dark:text-white break-all">
                              {item.ioc_value}
                            </div>
                            <div className="text-[10px] text-slate-500">
                              Created: {formatUtcDateTime(item.created_at)}
                              {item.expires_at ? ` · Exp: ${formatUtcDateTime(item.expires_at)}` : ''}
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="font-mono font-bold">{item.confidence_score}%</div>
                            <div className="text-[11px] text-slate-500 truncate max-w-[160px]">
                              {item.source}
                            </div>
                          </td>
                          {fuzzyMode && (
                            <td className="p-3 font-mono font-bold text-purple-600 dark:text-purple-400">
                              {item.similarity !== null && item.similarity !== undefined
                                ? `${(item.similarity * 100).toFixed(1)}%`
                                : '—'}
                            </td>
                          )}
                          <td className="p-3 text-right">
                            {item.is_active ? (
                              <RequirePermission permission={PERMISSIONS.IOCS_WRITE} mode="disable">
                                <button
                                  type="button"
                                  onClick={() => void handleDeactivate(item.id, item.ioc_value)}
                                  className="soc-btn-danger px-2 py-1 text-[10px]"
                                >
                                  <Trash2 className="w-3 h-3" /> Deactivate
                                </button>
                              </RequirePermission>
                            ) : (
                              <span className="text-[10px] font-mono text-slate-400">INACTIVE</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              <div className="px-4 py-2.5 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500">
                Showing {items.length} of {total} indicator(s)
              </div>
            </div>
          </div>
        </div>
      </RequirePermission>
    </div>
  );
}
