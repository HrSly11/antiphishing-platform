import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Eye,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
  XCircle,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import {
  formatUtcDateTime,
  getActionBadgeClasses,
  getVerdictBadgeClasses,
} from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type { AnalystLabelType, VerdictItem, VerdictPage } from '../types/domain';

export default function VerdictsPage() {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [verdictFilter, setVerdictFilter] = useState('');
  const [channelFilter, setChannelFilter] = useState('');
  const [labelFilter, setLabelFilter] = useState('');
  const [searchQ, setSearchQ] = useState('');

  const [data, setData] = useState<VerdictPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVerdict, setSelectedVerdict] = useState<VerdictItem | null>(null);
  const [labelingId, setLabelingId] = useState<string | null>(null);

  const fetchVerdicts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = {
        page,
        page_size: pageSize,
      };
      if (verdictFilter) params.verdict = verdictFilter;
      if (channelFilter) params.channel = channelFilter;
      if (labelFilter) params.analyst_label = labelFilter;
      if (searchQ.trim()) params.q = searchQ.trim();

      const res = await apiClient.get<VerdictPage>('/detection/verdicts', { params });
      setData(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, verdictFilter, channelFilter, labelFilter, searchQ]);

  useEffect(() => {
    void fetchVerdicts();
  }, [fetchVerdicts]);

  const handleSetLabel = async (verdictId: string, label: AnalystLabelType) => {
    setLabelingId(verdictId);
    setError(null);
    try {
      const res = await apiClient.patch<VerdictItem>(`/detection/verdicts/${verdictId}/label`, {
        label,
      });
      setData((prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((v) => (v.id === verdictId ? res.data : v)),
            }
          : prev,
      );
      if (selectedVerdict?.id === verdictId) {
        setSelectedVerdict(res.data);
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLabelingId(null);
    }
  };

  const openDetail = async (item: VerdictItem) => {
    setSelectedVerdict(item);
    try {
      const res = await apiClient.get<VerdictItem>(`/detection/verdicts/${item.id}`);
      setSelectedVerdict(res.data);
    } catch {
      // Keep row snapshot if detail call fails
    }
  };

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize));

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.DETECTION_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
              <ShieldAlert className="w-3.5 h-3.5" />
              DETECTION VERDICT LEDGER &amp; ANALYST CONFUSION FEEDBACK
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Detection Verdicts &amp; TP/FP Labeling
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Review persisted verdicts across all channels and classify True Positives / False Positives to calibrate live SOC KPIs.
            </p>
          </div>

          <button type="button" onClick={() => void fetchVerdicts()} className="soc-btn-secondary">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Ledger
          </button>
        </div>

        {/* Filter Bar */}
        <div className="soc-card p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="lg:col-span-2 relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search sender, domain, subject, correlation ID..."
              value={searchQ}
              onChange={(e) => {
                setSearchQ(e.target.value);
                setPage(1);
              }}
              className="soc-input pl-8"
            />
          </div>

          <select
            value={verdictFilter}
            onChange={(e) => {
              setVerdictFilter(e.target.value);
              setPage(1);
            }}
            className="soc-input"
          >
            <option value="">All Verdicts</option>
            <option value="MALICIOUS">MALICIOUS</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="CLEAN">CLEAN</option>
          </select>

          <select
            value={channelFilter}
            onChange={(e) => {
              setChannelFilter(e.target.value);
              setPage(1);
            }}
            className="soc-input"
          >
            <option value="">All Channels</option>
            <option value="EMAIL">EMAIL</option>
            <option value="SMS">SMS</option>
            <option value="WEB">WEB</option>
            <option value="QR">QR</option>
          </select>

          <select
            value={labelFilter}
            onChange={(e) => {
              setLabelFilter(e.target.value);
              setPage(1);
            }}
            className="soc-input"
          >
            <option value="">All Analyst Labels</option>
            <option value="UNREVIEWED">UNREVIEWED</option>
            <option value="TRUE_POSITIVE">TRUE_POSITIVE</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
        </div>

        {error && (
          <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Table */}
        <div className="soc-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                  <th className="p-3.5">Timestamp / Correlation</th>
                  <th className="p-3.5">Channel</th>
                  <th className="p-3.5">Sender &amp; Subject</th>
                  <th className="p-3.5">Verdict / Score</th>
                  <th className="p-3.5">Analyst Feedback</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center text-slate-500">
                      Loading detection verdicts...
                    </td>
                  </tr>
                ) : (data?.items.length ?? 0) === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center text-slate-500">
                      No detection verdicts match the selected filters.
                    </td>
                  </tr>
                ) : (
                  data?.items.map((v) => (
                    <tr
                      key={v.id}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition"
                    >
                      <td className="p-3.5 font-mono">
                        <div className="font-semibold text-slate-900 dark:text-slate-100">
                          {v.correlation_id}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {formatUtcDateTime(v.created_at)}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                          {v.channel}
                        </span>
                      </td>
                      <td className="p-3.5 max-w-xs">
                        <div className="font-semibold text-slate-900 dark:text-white truncate">
                          {v.subject}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 truncate">
                          {v.sender_email} → {v.recipient_email}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getVerdictBadgeClasses(
                              v.verdict,
                            )}`}
                          >
                            {v.verdict} ({v.risk_score})
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${getActionBadgeClasses(
                              v.action_taken,
                            )}`}
                          >
                            {v.action_taken}
                          </span>
                        </div>
                        {v.incident_id && v.incident_code && (
                          <Link
                            to={`/incidents/${v.incident_id}`}
                            className="inline-flex items-center gap-1 text-[10px] font-mono text-blue-600 dark:text-blue-400 hover:underline mt-1"
                          >
                            {v.incident_code} <ExternalLink className="w-2.5 h-2.5" />
                          </Link>
                        )}
                      </td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[10px] font-semibold border ${
                            v.analyst_label === 'TRUE_POSITIVE'
                              ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                              : v.analyst_label === 'FALSE_POSITIVE'
                                ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'
                                : 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20'
                          }`}
                        >
                          {v.analyst_label}
                        </span>
                      </td>
                      <td className="p-3.5 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                            <button
                              type="button"
                              disabled={labelingId === v.id}
                              onClick={() => void handleSetLabel(v.id, 'TRUE_POSITIVE')}
                              title="Mark True Positive"
                              className="px-2 py-1 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20 text-[10px] font-semibold inline-flex items-center gap-1"
                            >
                              <CheckCircle2 className="w-3 h-3" /> TP
                            </button>
                          </RequirePermission>
                          <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                            <button
                              type="button"
                              disabled={labelingId === v.id}
                              onClick={() => void handleSetLabel(v.id, 'FALSE_POSITIVE')}
                              title="Mark False Positive"
                              className="px-2 py-1 rounded border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20 text-[10px] font-semibold inline-flex items-center gap-1"
                            >
                              <XCircle className="w-3 h-3" /> FP
                            </button>
                          </RequirePermission>
                          <button
                            type="button"
                            onClick={() => void openDetail(v)}
                            className="soc-btn-secondary px-2 py-1 text-[10px]"
                          >
                            <Eye className="w-3 h-3" /> Inspect
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-500">
              Total verdicts: <strong>{data?.total ?? 0}</strong> · Page {page} of {totalPages}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="soc-btn-secondary px-2.5 py-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Prev
              </button>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="soc-btn-secondary px-2.5 py-1"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Verdict Forensic Detail Drawer */}
        {selectedVerdict && (
          <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/60 backdrop-blur-sm">
            <div className="w-full max-w-xl bg-white dark:bg-slate-950 border-l border-slate-200 dark:border-slate-800 h-full flex flex-col shadow-2xl">
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <div>
                  <div className="font-mono text-xs font-bold text-blue-600 dark:text-blue-400">
                    {selectedVerdict.correlation_id}
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                    Forensic Detection Verdict Detail
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedVerdict(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2.5 py-1 rounded font-mono font-bold border ${getVerdictBadgeClasses(
                        selectedVerdict.verdict,
                      )}`}
                    >
                      {selectedVerdict.verdict} · {selectedVerdict.risk_score}/100
                    </span>
                    <span
                      className={`px-2 py-1 rounded font-mono border ${getActionBadgeClasses(
                        selectedVerdict.action_taken,
                      )}`}
                    >
                      {selectedVerdict.action_taken}
                    </span>
                  </div>
                  <span className="font-mono text-slate-500">
                    Latency: {selectedVerdict.latency_ms} ms
                  </span>
                </div>

                <div className="soc-card-muted p-3.5 space-y-1.5">
                  <div>
                    <span className="soc-label">Subject</span>
                    <div className="font-semibold text-slate-900 dark:text-white">
                      {selectedVerdict.subject}
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                    <div>
                      <span className="soc-label">Sender</span>
                      <div className="font-mono break-all">{selectedVerdict.sender_email}</div>
                    </div>
                    <div>
                      <span className="soc-label">Recipient</span>
                      <div className="font-mono break-all">{selectedVerdict.recipient_email}</div>
                    </div>
                  </div>
                </div>

                <div className="soc-card-muted p-3">
                  <span className="soc-label mb-1">Summary</span>
                  <p className="text-slate-700 dark:text-slate-300">{selectedVerdict.summary}</p>
                </div>

                <div className="flex items-center justify-between gap-2 soc-card p-3">
                  <div>
                    <div className="soc-label">Analyst Feedback Label</div>
                    <div className="font-mono font-bold text-slate-900 dark:text-white">
                      {selectedVerdict.analyst_label}
                    </div>
                  </div>
                  <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => void handleSetLabel(selectedVerdict.id, 'TRUE_POSITIVE')}
                        className="soc-btn-secondary py-1 px-2.5"
                      >
                        Mark TP
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleSetLabel(selectedVerdict.id, 'FALSE_POSITIVE')}
                        className="soc-btn-secondary py-1 px-2.5"
                      >
                        Mark FP
                      </button>
                    </div>
                  </RequirePermission>
                </div>

                <div className="space-y-2">
                  <div className="soc-label">
                    Signals ({selectedVerdict.signals_meta.length})
                  </div>
                  {selectedVerdict.signals_meta.length === 0 ? (
                    <div className="text-slate-500">No risk signals recorded.</div>
                  ) : (
                    selectedVerdict.signals_meta.map((sig, i) => (
                      <div key={`${sig.name}-${i}`} className="soc-card-muted p-2.5">
                        <div className="flex justify-between font-mono font-bold">
                          <span>{sig.name}</span>
                          <span className="text-amber-600 dark:text-amber-400">
                            +{sig.weight} pts
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-600 dark:text-slate-400">
                          {sig.reason}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="space-y-1">
                  <div className="soc-label">Headers &amp; Forensic Metadata</div>
                  <pre className="p-3 rounded-lg bg-slate-900 text-slate-200 font-mono text-[10px] overflow-x-auto">
                    {JSON.stringify(selectedVerdict.headers_meta, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </RequirePermission>
    </div>
  );
}
