import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  BellRing,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Plus,
  RefreshCw,
  Siren,
  X,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import {
  formatSlaCountdown,
  formatUtcDateTime,
  getIncidentStatusClasses,
  getSeverityBadgeClasses,
} from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type {
  ChannelType,
  IncidentDetail,
  IncidentPage,
  ManualIncidentCreatePayload,
  SeverityType,
} from '../types/domain';

export default function IncidentsPage() {
  const navigate = useNavigate();

  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [overdueOnly, setOverdueOnly] = useState(false);

  const [data, setData] = useState<IncidentPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [bannerMsg, setBannerMsg] = useState<string | null>(null);
  const [escalating, setEscalating] = useState(false);

  // Manual Incident Creation Modal
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createForm, setCreateForm] = useState<ManualIncidentCreatePayload>({
    severity: 'HIGH',
    subject: 'Spear-Phishing Campaign Targeting Corporate Treasury',
    sender_email: 'cfo-spoof@ejecutivo-finanzas-corp.com',
    recipient_email: 'tesoreria@bancocentral.com',
    summary: 'Manual SOC escalation opened after out-of-band executive verification.',
    notes: 'Initiating domain sinkhole and Entra ID session audit.',
    channel: 'EMAIL',
    risk_score: 88,
  });

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number | boolean> = {
        page,
        page_size: pageSize,
      };
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      if (overdueOnly) params.overdue_only = true;

      const res = await apiClient.get<IncidentPage>('/incidents', { params });
      setData(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, statusFilter, severityFilter, overdueOnly]);

  useEffect(() => {
    void fetchIncidents();
  }, [fetchIncidents]);

  const handleEscalateOverdue = async () => {
    setEscalating(true);
    setError(null);
    setBannerMsg(null);
    try {
      const res = await apiClient.post<{
        escalated_count: number;
        incident_codes: string[];
      }>('/incidents/escalate-overdue');
      const count = res.data.escalated_count;
      const codes = res.data.incident_codes.join(', ');
      setBannerMsg(
        count > 0
          ? `SLA Escalation Worker swept ${count} overdue incident(s) and queued n8n SOAR alerts: ${codes}`
          : 'SLA Sweep completed: 0 un-escalated overdue incidents found.',
      );
      await fetchIncidents();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setEscalating(false);
    }
  };

  const handleCreateManual = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const res = await apiClient.post<IncidentDetail>('/incidents', createForm);
      setCreateOpen(false);
      navigate(`/incidents/${res.data.id}`);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setCreating(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize));

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.INCIDENTS_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-red-600 dark:text-red-400">
              <Siren className="w-3.5 h-3.5" />
              SOC CASE MANAGEMENT &amp; BANKING SLA ENFORCEMENT
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              SOC Phishing Incidents &amp; SLA Queue
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Deterministic incident lifecycle: <code>OPEN → TRIAGED → INVESTIGATING → CONTAINED → CLOSED</code> (CRITICAL SLA: 15m · HIGH SLA: 60m).
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => void fetchIncidents()} className="soc-btn-secondary">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
              <button
                type="button"
                disabled={escalating}
                onClick={() => void handleEscalateOverdue()}
                className="soc-btn-danger py-2"
              >
                <BellRing className="w-3.5 h-3.5" />
                {escalating ? 'Sweeping SLAs...' : 'Escalate Overdue SLAs'}
              </button>
            </RequirePermission>

            <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
              <button
                type="button"
                onClick={() => setCreateOpen(true)}
                className="soc-btn-primary"
              >
                <Plus className="w-4 h-4" />
                New Manual Incident
              </button>
            </RequirePermission>
          </div>
        </div>

        {/* Filters */}
        <div className="soc-card p-4 flex flex-wrap items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="soc-input sm:w-48"
          >
            <option value="">All Lifecycle States</option>
            <option value="OPEN">OPEN</option>
            <option value="TRIAGED">TRIAGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="CLOSED">CLOSED</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="soc-input sm:w-44"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL (15m SLA)</option>
            <option value="HIGH">HIGH (60m SLA)</option>
            <option value="MEDIUM">MEDIUM (4h SLA)</option>
            <option value="LOW">LOW (24h SLA)</option>
          </select>

          <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300 cursor-pointer px-2">
            <input
              type="checkbox"
              checked={overdueOnly}
              onChange={(e) => {
                setOverdueOnly(e.target.checked);
                setPage(1);
              }}
              className="rounded border-slate-400"
            />
            <span>Overdue SLAs Only</span>
          </label>
        </div>

        {bannerMsg && (
          <div className="p-3.5 rounded-xl border border-blue-500/30 bg-blue-500/10 text-xs text-blue-700 dark:text-blue-300">
            {bannerMsg}
          </div>
        )}

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Incidents Table */}
        <div className="soc-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                  <th className="p-3.5">Incident Code</th>
                  <th className="p-3.5">Severity / Status</th>
                  <th className="p-3.5">Threat Subject &amp; Sender</th>
                  <th className="p-3.5">Assignee</th>
                  <th className="p-3.5">SLA Posture</th>
                  <th className="p-3.5 text-right">Case Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center text-slate-500">
                      Loading SOC incidents...
                    </td>
                  </tr>
                ) : (data?.items.length ?? 0) === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center text-slate-500">
                      No incidents match the selected filters.
                    </td>
                  </tr>
                ) : (
                  data?.items.map((inc) => {
                    const sla = formatSlaCountdown(inc.sla_deadline, inc.status);
                    const isOverdue = inc.sla_overdue || sla.overdue;
                    return (
                      <tr
                        key={inc.id}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition"
                      >
                        <td className="p-3.5 font-mono">
                          <Link
                            to={`/incidents/${inc.id}`}
                            className="font-bold text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            {inc.incident_code}
                          </Link>
                          <div className="text-[10px] text-slate-500">
                            {formatUtcDateTime(inc.created_at)}
                          </div>
                        </td>
                        <td className="p-3.5">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span
                              className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${getSeverityBadgeClasses(
                                inc.severity,
                              )}`}
                            >
                              {inc.severity}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${getIncidentStatusClasses(
                                inc.status,
                              )}`}
                            >
                              {inc.status}
                            </span>
                          </div>
                          {inc.resolution && (
                            <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 mt-1">
                              {inc.resolution}
                            </div>
                          )}
                        </td>
                        <td className="p-3.5 max-w-xs">
                          <div className="font-semibold text-slate-900 dark:text-white truncate">
                            {inc.subject ?? '(Manual Incident)'}
                          </div>
                          <div className="font-mono text-[11px] text-slate-500 truncate">
                            {inc.sender_email ?? '—'} · Score: {inc.risk_score ?? '—'}/100
                          </div>
                        </td>
                        <td className="p-3.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                          {inc.assigned_to ?? (
                            <span className="text-slate-400 italic">Unassigned</span>
                          )}
                        </td>
                        <td className="p-3.5">
                          <div className="flex items-center gap-1.5">
                            {isOverdue ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-red-500/15 text-red-700 dark:text-red-300 border border-red-500/35">
                                <AlertTriangle className="w-3 h-3" /> {sla.label}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25">
                                {sla.label}
                              </span>
                            )}
                            {inc.is_escalated && (
                              <span className="px-1.5 py-0.5 rounded font-mono text-[9px] font-bold bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                                ESCALATED
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3.5 text-right">
                          <Link
                            to={`/incidents/${inc.id}`}
                            className="soc-btn-secondary px-2.5 py-1 text-[11px]"
                          >
                            Investigate <ExternalLink className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-500">
              Total incidents: <strong>{data?.total ?? 0}</strong> · Page {page} of {totalPages}
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

        {/* New Manual Incident Modal */}
        {createOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4">
            <div className="soc-card w-full max-w-lg overflow-hidden shadow-2xl">
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Open Manual SOC Phishing Incident
                </h3>
                <button
                  type="button"
                  onClick={() => setCreateOpen(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <form onSubmit={handleCreateManual} className="p-5 space-y-3 text-xs">
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="soc-label mb-1">Severity</label>
                    <select
                      value={createForm.severity}
                      onChange={(e) =>
                        setCreateForm({
                          ...createForm,
                          severity: e.target.value as SeverityType,
                        })
                      }
                      className="soc-input"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                  <div>
                    <label className="soc-label mb-1">Channel</label>
                    <select
                      value={createForm.channel}
                      onChange={(e) =>
                        setCreateForm({
                          ...createForm,
                          channel: e.target.value as ChannelType,
                        })
                      }
                      className="soc-input"
                    >
                      <option value="EMAIL">EMAIL</option>
                      <option value="SMS">SMS</option>
                      <option value="QR">QR</option>
                      <option value="WEB">WEB</option>
                    </select>
                  </div>
                  <div>
                    <label className="soc-label mb-1">Risk Score</label>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={createForm.risk_score}
                      onChange={(e) =>
                        setCreateForm({
                          ...createForm,
                          risk_score: Number(e.target.value),
                        })
                      }
                      className="soc-input font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="soc-label mb-1">Subject / Threat Title</label>
                  <input
                    type="text"
                    required
                    value={createForm.subject}
                    onChange={(e) => setCreateForm({ ...createForm, subject: e.target.value })}
                    className="soc-input"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="soc-label mb-1">Hostile Sender</label>
                    <input
                      type="text"
                      required
                      value={createForm.sender_email}
                      onChange={(e) =>
                        setCreateForm({ ...createForm, sender_email: e.target.value })
                      }
                      className="soc-input font-mono"
                    />
                  </div>
                  <div>
                    <label className="soc-label mb-1">Targeted Recipient</label>
                    <input
                      type="text"
                      required
                      value={createForm.recipient_email}
                      onChange={(e) =>
                        setCreateForm({ ...createForm, recipient_email: e.target.value })
                      }
                      className="soc-input font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="soc-label mb-1">Executive Summary</label>
                  <textarea
                    rows={2}
                    required
                    value={createForm.summary}
                    onChange={(e) => setCreateForm({ ...createForm, summary: e.target.value })}
                    className="soc-input"
                  />
                </div>

                <div>
                  <label className="soc-label mb-1">Initial Timeline Note</label>
                  <input
                    type="text"
                    value={createForm.notes ?? ''}
                    onChange={(e) => setCreateForm({ ...createForm, notes: e.target.value })}
                    className="soc-input"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setCreateOpen(false)}
                    className="soc-btn-secondary"
                  >
                    Cancel
                  </button>
                  <button type="submit" disabled={creating} className="soc-btn-primary">
                    {creating ? 'Creating Ticket...' : 'Create SOC Incident'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </RequirePermission>
    </div>
  );
}
