import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Bot,
  CheckCircle2,
  Clock,
  MessageSquarePlus,
  Shield,
  Sparkles,
  UserCheck,
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
  IncidentBriefingResponse,
  IncidentDetail,
  IncidentResolutionType,
  IncidentStatusType,
} from '../types/domain';

const LIFECYCLE_STEPS: IncidentStatusType[] = [
  'OPEN',
  'TRIAGED',
  'INVESTIGATING',
  'CONTAINED',
  'CLOSED',
];

const NEXT_TRANSITIONS: Record<IncidentStatusType, IncidentStatusType[]> = {
  OPEN: ['TRIAGED', 'CLOSED'],
  TRIAGED: ['INVESTIGATING', 'CLOSED'],
  INVESTIGATING: ['CONTAINED', 'CLOSED'],
  CONTAINED: ['CLOSED'],
  CLOSED: [],
};

const RESOLUTION_OPTIONS: IncidentResolutionType[] = [
  'TRUE_POSITIVE',
  'FALSE_POSITIVE',
  'BENIGN_POLICY_VIOLATION',
  'DUPLICATE',
];

const DEFAULT_ANALYSTS = [
  { email: 'socl1@bancocentral.com', label: 'Lucia Rojas (SOC_L1)' },
  { email: 'socl2@bancocentral.com', label: 'Carlos Paredes (SOC_L2)' },
  { email: 'admin@bancocentral.com', label: 'Valeria Mendoza (ADMIN)' },
];

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Transition state
  const [targetStatus, setTargetStatus] = useState<IncidentStatusType>('TRIAGED');
  const [resolution, setResolution] = useState<IncidentResolutionType>('TRUE_POSITIVE');
  const [transitionNote, setTransitionNote] = useState('');
  const [transitionBusy, setTransitionBusy] = useState(false);

  // Assignee state
  const [assigneeEmail, setAssigneeEmail] = useState('socl2@bancocentral.com');
  const [assignBusy, setAssignBusy] = useState(false);

  // Investigation Note state
  const [noteText, setNoteText] = useState('');
  const [noteBusy, setNoteBusy] = useState(false);

  // AI Executive Summary state
  const [briefing, setBriefing] = useState<IncidentBriefingResponse | null>(null);
  const [briefingBusy, setBriefingBusy] = useState(false);

  const loadIncident = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.get<IncidentDetail>(`/incidents/${id}`);
      setIncident(res.data);
      const allowed = NEXT_TRANSITIONS[res.data.status] ?? [];
      if (allowed.length > 0) {
        setTargetStatus(allowed[0]);
      }
      if (res.data.assigned_to) {
        setAssigneeEmail(res.data.assigned_to);
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void loadIncident();
  }, [loadIncident]);

  const handleTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    setTransitionBusy(true);
    setError(null);
    try {
      const payload: Record<string, string> = {
        new_status: targetStatus,
      };
      if (targetStatus === 'CLOSED') {
        payload.resolution = resolution;
      }
      if (transitionNote.trim()) {
        payload.note = transitionNote.trim();
      }
      const res = await apiClient.post<IncidentDetail>(
        `/incidents/${incident.id}/transition`,
        payload,
      );
      setIncident(res.data);
      setTransitionNote('');
      const nextAllowed = NEXT_TRANSITIONS[res.data.status] ?? [];
      if (nextAllowed.length > 0) {
        setTargetStatus(nextAllowed[0]);
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setTransitionBusy(false);
    }
  };

  const handleAssign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    setAssignBusy(true);
    setError(null);
    try {
      const res = await apiClient.post<IncidentDetail>(`/incidents/${incident.id}/assign`, {
        assignee_id: assigneeEmail,
      });
      setIncident(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setAssignBusy(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !noteText.trim()) return;
    setNoteBusy(true);
    setError(null);
    try {
      await apiClient.post(`/incidents/${incident.id}/notes`, { note: noteText.trim() });
      setNoteText('');
      await loadIncident();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setNoteBusy(false);
    }
  };

  const handleSummarize = async () => {
    if (!incident) return;
    setBriefingBusy(true);
    setError(null);
    try {
      const res = await apiClient.post<IncidentBriefingResponse>(
        `/incidents/${incident.id}/summarize`,
      );
      setBriefing(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBriefingBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center text-sm text-slate-500">
        Loading SOC incident case file...
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-8 max-w-2xl mx-auto space-y-4">
        <div className="soc-card p-6 text-center text-xs text-red-600 dark:text-red-300">
          {error ?? 'Incident not found'}
        </div>
        <Link to="/incidents" className="soc-btn-secondary">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Incidents
        </Link>
      </div>
    );
  }

  const sla = formatSlaCountdown(incident.sla_deadline, incident.status);
  const allowedNext = NEXT_TRANSITIONS[incident.status] ?? [];

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.INCIDENTS_READ} mode="page">
        {/* Breadcrumb & Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <Link to="/incidents" className="soc-btn-secondary">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to SOC Queue
          </Link>

          <button
            type="button"
            disabled={briefingBusy}
            onClick={() => void handleSummarize()}
            className="soc-btn-primary"
          >
            <Sparkles className="w-4 h-4" />
            {briefingBusy ? 'Generating CISO Briefing...' : 'Generate AI Executive Summary'}
          </button>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Case Banner */}
        <div className="soc-card p-5 sm:p-6 space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-sm font-black text-blue-600 dark:text-blue-400">
                  {incident.incident_code}
                </span>
                <span
                  className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${getSeverityBadgeClasses(
                    incident.severity,
                  )}`}
                >
                  {incident.severity}
                </span>
                <span
                  className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${getIncidentStatusClasses(
                    incident.status,
                  )}`}
                >
                  {incident.status}
                </span>
                {incident.resolution && (
                  <span className="px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                    RESOLUTION: {incident.resolution}
                  </span>
                )}
              </div>
              <h1 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white">
                {incident.subject ?? 'SOC Phishing Case'}
              </h1>
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                Sender: {incident.sender_email ?? '—'} → Recipient:{' '}
                {incident.recipient_email ?? '—'} · Channel: {incident.channel ?? 'EMAIL'} · Score:{' '}
                {incident.risk_score ?? '—'}/100
              </div>
            </div>

            <div className="soc-card-muted p-3.5 space-y-1 shrink-0">
              <div className="soc-label flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" /> SLA Deadline Posture
              </div>
              <div
                className={`font-mono text-xs font-bold flex items-center gap-1.5 ${
                  incident.sla_overdue || sla.overdue
                    ? 'text-red-600 dark:text-red-400'
                    : 'text-emerald-600 dark:text-emerald-400'
                }`}
              >
                {(incident.sla_overdue || sla.overdue) && <AlertTriangle className="w-3.5 h-3.5" />}
                {sla.label}
              </div>
              <div className="text-[10px] font-mono text-slate-500">
                Deadline: {formatUtcDateTime(incident.sla_deadline)}
              </div>
            </div>
          </div>

          {/* Visual 5-Step Lifecycle Stepper */}
          <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-2">
            {LIFECYCLE_STEPS.map((st, idx) => {
              const currentIdx = LIFECYCLE_STEPS.indexOf(incident.status);
              const reached = idx <= currentIdx;
              return (
                <div key={st} className="flex items-center gap-2">
                  <span
                    className={`px-3 py-1 rounded-full font-mono text-[11px] font-bold border ${
                      st === incident.status
                        ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
                        : reached
                          ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-100 dark:bg-slate-900 text-slate-400 border-slate-200 dark:border-slate-800'
                    }`}
                  >
                    {idx + 1}. {st}
                  </span>
                  {idx < LIFECYCLE_STEPS.length - 1 && (
                    <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* AI CISO Executive Briefing Card (when generated) */}
        {briefing && (
          <div className="soc-card p-5 border-blue-500/40 space-y-3 text-xs">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 font-bold text-sm text-slate-900 dark:text-white">
                <Bot className="w-4 h-4 text-blue-500" />
                LangChain Executive CISO Incident Briefing
              </div>
              <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-blue-500/15 text-blue-700 dark:text-blue-300 border border-blue-500/30">
                Engine: {briefing.engine}
              </span>
            </div>

            <p className="soc-card-muted p-3.5 text-slate-700 dark:text-slate-200 leading-relaxed">
              {briefing.summary}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <div className="soc-label">Recommended Containment Actions</div>
                <ul className="space-y-1">
                  {briefing.recommended_actions.map((act, i) => (
                    <li
                      key={i}
                      className="soc-card-muted p-2 flex items-start gap-2 text-slate-700 dark:text-slate-300"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                      <span>{act}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="space-y-1.5">
                <div className="soc-label">Mapped Regulatory Controls</div>
                <ul className="space-y-1">
                  {briefing.compliance_controls.map((ctrl, i) => (
                    <li
                      key={i}
                      className="soc-card-muted p-2 flex items-start gap-2 font-mono text-[11px] text-slate-700 dark:text-slate-300"
                    >
                      <Shield className="w-3.5 h-3.5 text-blue-500 shrink-0 mt-0.5" />
                      <span>{ctrl}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left: Controls + Linked IOCs + Signals */}
          <div className="lg:col-span-5 space-y-5">
            {/* Lifecycle Transition Card */}
            <div className="soc-card p-5 space-y-3 text-xs">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                State Machine Transition
              </h2>
              {allowedNext.length === 0 ? (
                <div className="soc-card-muted p-3 text-emerald-700 dark:text-emerald-300 font-medium">
                  This incident is in terminal <code>CLOSED</code> state ({incident.resolution}).
                </div>
              ) : (
                <form onSubmit={handleTransition} className="space-y-3">
                  <div>
                    <label className="soc-label mb-1">Next Allowed State</label>
                    <select
                      value={targetStatus}
                      onChange={(e) => setTargetStatus(e.target.value as IncidentStatusType)}
                      className="soc-input font-mono"
                    >
                      {allowedNext.map((st) => (
                        <option key={st} value={st}>
                          {incident.status} → {st}
                        </option>
                      ))}
                    </select>
                  </div>

                  {targetStatus === 'CLOSED' && (
                    <div>
                      <label className="soc-label mb-1">Mandatory Closure Resolution</label>
                      <select
                        value={resolution}
                        onChange={(e) =>
                          setResolution(e.target.value as IncidentResolutionType)
                        }
                        className="soc-input font-mono"
                      >
                        {RESOLUTION_OPTIONS.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

                  <div>
                    <label className="soc-label mb-1">Transition Justification Note</label>
                    <input
                      type="text"
                      placeholder="Document containment or triage findings..."
                      value={transitionNote}
                      onChange={(e) => setTransitionNote(e.target.value)}
                      className="soc-input"
                    />
                  </div>

                  <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                    <button
                      type="submit"
                      disabled={transitionBusy}
                      className="soc-btn-primary w-full"
                    >
                      {transitionBusy ? 'Applying Transition...' : `Transition to ${targetStatus}`}
                    </button>
                  </RequirePermission>
                </form>
              )}
            </div>

            {/* Analyst Assignment Card */}
            <form onSubmit={handleAssign} className="soc-card p-5 space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Analyst Assignment
                </h2>
                <span className="font-mono text-[11px] text-slate-500">
                  Current: {incident.assigned_to ?? 'Unassigned'}
                </span>
              </div>

              <select
                value={assigneeEmail}
                onChange={(e) => setAssigneeEmail(e.target.value)}
                className="soc-input font-mono"
              >
                {DEFAULT_ANALYSTS.map((a) => (
                  <option key={a.email} value={a.email}>
                    {a.label} — {a.email}
                  </option>
                ))}
              </select>

              <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                <button type="submit" disabled={assignBusy} className="soc-btn-secondary w-full">
                  <UserCheck className="w-3.5 h-3.5" />
                  {assignBusy ? 'Assigning...' : 'Assign Case Owner'}
                </button>
              </RequirePermission>
            </form>

            {/* Linked IOCs & Detection Signals */}
            <div className="soc-card p-5 space-y-3 text-xs">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                Linked IOCs ({incident.iocs.length}) &amp; Verdict Signals ({incident.signals.length})
              </h2>

              <p className="soc-card-muted p-2.5 text-slate-600 dark:text-slate-300">
                {incident.verdict_summary || incident.summary}
              </p>

              {incident.iocs.length > 0 && (
                <div className="space-y-1.5">
                  <div className="soc-label">Correlated Indicators</div>
                  {incident.iocs.map((ioc) => (
                    <div
                      key={ioc.id}
                      className="soc-card-muted p-2 flex items-center justify-between font-mono text-[11px]"
                    >
                      <span className="truncate">
                        [{ioc.ioc_type}] {ioc.ioc_value}
                      </span>
                      <span className="text-red-600 dark:text-red-400 shrink-0">
                        {ioc.list_type}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {incident.signals.length > 0 && (
                <div className="space-y-1.5">
                  <div className="soc-label">Detection Signals</div>
                  {incident.signals.map((sig, i) => (
                    <div key={`${sig.name}-${i}`} className="soc-card-muted p-2">
                      <div className="flex justify-between font-mono font-bold">
                        <span>{sig.name}</span>
                        <span className="text-amber-600 dark:text-amber-400">
                          +{sig.weight} pts
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500">{sig.reason}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right: Immutable Event Timeline + Add Investigation Note */}
          <div className="lg:col-span-7 space-y-5">
            <form onSubmit={handleAddNote} className="soc-card p-5 space-y-3 text-xs">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                Append Immutable Forensic Note
              </h2>
              <textarea
                rows={3}
                required
                placeholder="Document SIEM correlation, mailbox purge confirmation, or IdP token revocation..."
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                className="soc-input"
              />
              <div className="flex justify-end">
                <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
                  <button type="submit" disabled={noteBusy} className="soc-btn-primary">
                    <MessageSquarePlus className="w-3.5 h-3.5" />
                    {noteBusy ? 'Appending...' : 'Add Timeline Note'}
                  </button>
                </RequirePermission>
              </div>
            </form>

            <div className="soc-card p-5 space-y-4 text-xs">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Immutable Case Event Timeline ({incident.events.length})
                </h2>
                <span className="text-[11px] font-mono text-slate-500">
                  Chronological Audit Sequence
                </span>
              </div>

              <div className="space-y-3">
                {incident.events.map((ev) => (
                  <div
                    key={ev.id}
                    className="soc-card-muted p-3.5 border-l-4 border-l-blue-500 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-blue-500/15 text-blue-700 dark:text-blue-300">
                          {ev.event_type}
                        </span>
                        {ev.from_status && ev.to_status && ev.from_status !== ev.to_status && (
                          <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                            {ev.from_status} → <strong>{ev.to_status}</strong>
                          </span>
                        )}
                      </div>
                      <span className="font-mono text-[10px] text-slate-500">
                        {formatUtcDateTime(ev.created_at)}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-500">Actor: {ev.actor}</div>
                    {ev.note && (
                      <p className="text-slate-800 dark:text-slate-200 pt-1">{ev.note}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </RequirePermission>
    </div>
  );
}
