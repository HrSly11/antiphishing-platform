import { useCallback, useEffect, useState } from 'react';
import { Crosshair, Database, Search, Shield, ShieldAlert } from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import { formatUtcDateTime, getVerdictBadgeClasses } from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type { ThreatHuntingResponse } from '../types/domain';

const HUNT_PRESETS = [
  { label: 'Lookalike: bancocentral', q: 'bancocentral' },
  { label: 'Bulletproof IP: 185.220.101.5', q: '185.220.101.5' },
  { label: 'Token Harvester Lure', q: 'token' },
  { label: 'Quishing .top Infrastructure', q: 'qr-sso' },
];

export default function ThreatHuntingPage() {
  const [query, setQuery] = useState('bancocentral');
  const [channel, setChannel] = useState('');
  const [verdict, setVerdict] = useState('');
  const [minScore, setMinScore] = useState<string>('');

  const [results, setResults] = useState<ThreatHuntingResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const executeHunt = useCallback(
    async (qOverride?: string) => {
      const q = (qOverride ?? query).trim();
      if (q.length < 2) return;
      setLoading(true);
      setError(null);
      try {
        const params: Record<string, string | number> = { q, limit: 25 };
        if (channel) params.channel = channel;
        if (verdict) params.verdict = verdict;
        if (minScore !== '') params.min_score = Number(minScore);

        const res = await apiClient.get<ThreatHuntingResponse>('/threat-hunting/search', {
          params,
        });
        setResults(res.data);
      } catch (err) {
        setError(extractApiError(err));
      } finally {
        setLoading(false);
      }
    },
    [query, channel, verdict, minScore],
  );

  useEffect(() => {
    void executeHunt('bancocentral');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.HUNTING_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 space-y-2">
          <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-purple-600 dark:text-purple-400">
            <Crosshair className="w-3.5 h-3.5" />
            UNIFIED PG_TRGM CORRELATION ACROSS VERDICTS · IOCS · PUBLIC FEEDS
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            Multi-Entity Threat Hunting Workbench
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Execute trigram similarity hunting across historical detection verdicts, active IOC lists, and OpenPhish/PhishTank corpus samples simultaneously.
          </p>
        </div>

        {/* Query Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void executeHunt();
          }}
          className="soc-card p-4 space-y-3"
        >
          <div className="flex flex-wrap gap-1.5">
            {HUNT_PRESETS.map((p) => (
              <button
                key={p.q}
                type="button"
                onClick={() => {
                  setQuery(p.q);
                  void executeHunt(p.q);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 hover:border-purple-500 text-[11px] font-mono text-slate-700 dark:text-slate-300"
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
            <div className="lg:col-span-2 relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                required
                minLength={2}
                placeholder="Domain, sender, IP, subject, typosquat..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="soc-input pl-8 font-mono"
              />
            </div>

            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="soc-input"
            >
              <option value="">All Channels</option>
              <option value="EMAIL">EMAIL</option>
              <option value="SMS">SMS</option>
              <option value="WEB">WEB</option>
              <option value="QR">QR</option>
            </select>

            <select
              value={verdict}
              onChange={(e) => setVerdict(e.target.value)}
              className="soc-input"
            >
              <option value="">All Verdicts</option>
              <option value="MALICIOUS">MALICIOUS</option>
              <option value="SUSPICIOUS">SUSPICIOUS</option>
              <option value="CLEAN">CLEAN</option>
            </select>

            <input
              type="number"
              min={0}
              max={100}
              placeholder="Min Score (0-100)"
              value={minScore}
              onChange={(e) => setMinScore(e.target.value)}
              className="soc-input font-mono"
            />

            <button type="submit" disabled={loading} className="soc-btn-primary">
              <Crosshair className="w-3.5 h-3.5" />
              {loading ? 'Hunting...' : 'Execute Hunt'}
            </button>
          </div>
        </form>

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {results && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="soc-card p-4 flex items-center justify-between">
                <div>
                  <div className="soc-label">Correlated Verdicts</div>
                  <div className="text-2xl font-black text-red-600 dark:text-red-400">
                    {results.verdicts.length}
                  </div>
                </div>
                <ShieldAlert className="w-6 h-6 text-red-500/70" />
              </div>
              <div className="soc-card p-4 flex items-center justify-between">
                <div>
                  <div className="soc-label">Matched IOCs</div>
                  <div className="text-2xl font-black text-blue-600 dark:text-blue-400">
                    {results.iocs.length}
                  </div>
                </div>
                <Shield className="w-6 h-6 text-blue-500/70" />
              </div>
              <div className="soc-card p-4 flex items-center justify-between">
                <div>
                  <div className="soc-label">Public Dataset Hits</div>
                  <div className="text-2xl font-black text-purple-600 dark:text-purple-400">
                    {results.dataset_samples.length}
                  </div>
                </div>
                <Database className="w-6 h-6 text-purple-500/70" />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Column 1: Verdicts */}
              <div className="soc-card p-4 space-y-3 text-xs">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  1. Detection Verdicts ({results.verdicts.length})
                </h2>
                {results.verdicts.length === 0 ? (
                  <div className="text-slate-500 py-4">No verdict matches.</div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                    {results.verdicts.map((v) => (
                      <div key={v.id} className="soc-card-muted p-3 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${getVerdictBadgeClasses(
                              v.verdict,
                            )}`}
                          >
                            {v.verdict} · {v.risk_score}
                          </span>
                          <span className="font-mono text-[10px] text-purple-600 dark:text-purple-400 font-bold">
                            sim {((v.similarity ?? 0) * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="font-semibold text-slate-900 dark:text-white truncate">
                          {v.subject}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 break-all">
                          {v.sender_email}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          {v.channel} · {formatUtcDateTime(v.created_at)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Column 2: IOCs */}
              <div className="soc-card p-4 space-y-3 text-xs">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  2. Active IOC Lists ({results.iocs.length})
                </h2>
                {results.iocs.length === 0 ? (
                  <div className="text-slate-500 py-4">No IOC matches.</div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                    {results.iocs.map((ioc) => (
                      <div key={ioc.id} className="soc-card-muted p-3 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                              ioc.list_type === 'WHITELIST'
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                                : 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30'
                            }`}
                          >
                            {ioc.list_type} · {ioc.ioc_type}
                          </span>
                          <span className="font-mono text-[10px] text-purple-600 dark:text-purple-400 font-bold">
                            sim {((ioc.similarity ?? 0) * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="font-mono font-bold text-slate-900 dark:text-white break-all">
                          {ioc.ioc_value}
                        </div>
                        <div className="text-[11px] text-slate-500">
                          Conf: {ioc.confidence_score}% · {ioc.source}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Column 3: Dataset Samples */}
              <div className="soc-card p-4 space-y-3 text-xs">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  3. Public Phishing Corpus ({results.dataset_samples.length})
                </h2>
                {results.dataset_samples.length === 0 ? (
                  <div className="text-slate-500 py-4">No dataset sample matches.</div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                    {results.dataset_samples.map((s) => (
                      <div key={s.id} className="soc-card-muted p-3 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-blue-500/15 text-blue-700 dark:text-blue-300">
                            {s.source}
                          </span>
                          {s.similarity !== undefined && (
                            <span className="font-mono text-[10px] text-purple-600 dark:text-purple-400 font-bold">
                              sim {(s.similarity * 100).toFixed(0)}%
                            </span>
                          )}
                        </div>
                        <div className="font-mono font-semibold text-slate-900 dark:text-white break-all">
                          {s.domain}
                        </div>
                        <div className="font-mono text-[10px] text-slate-500 break-all">
                          {s.url}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </RequirePermission>
    </div>
  );
}
