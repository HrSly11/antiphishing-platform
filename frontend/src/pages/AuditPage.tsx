import { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Link2,
  RefreshCw,
  Scale,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import { formatUtcDateTime } from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type {
  AuditChainVerification,
  AuditLogPage,
  CompliancePostureResponse,
} from '../types/domain';

type AuditTab = 'compliance' | 'logs';

export default function AuditPage() {
  const [tab, setTab] = useState<AuditTab>('compliance');

  const [compliance, setCompliance] = useState<CompliancePostureResponse | null>(null);
  const [chain, setChain] = useState<AuditChainVerification | null>(null);
  const [logsPage, setLogsPage] = useState<AuditLogPage | null>(null);

  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');

  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadComplianceAndChain = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [compRes, chainRes] = await Promise.all([
        apiClient.get<CompliancePostureResponse>('/audit/compliance'),
        apiClient.get<AuditChainVerification>('/audit/verify-chain'),
      ]);
      setCompliance(compRes.data);
      setChain(chainRes.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAuditLogs = useCallback(async () => {
    try {
      const params: Record<string, string | number> = {
        page,
        page_size: 20,
      };
      if (actionFilter.trim()) params.action = actionFilter.trim();
      if (userFilter.trim()) params.user_email = userFilter.trim();
      const res = await apiClient.get<AuditLogPage>('/audit/logs', { params });
      setLogsPage(res.data);
    } catch (err) {
      setError(extractApiError(err));
    }
  }, [page, actionFilter, userFilter]);

  useEffect(() => {
    void loadComplianceAndChain();
  }, [loadComplianceAndChain]);

  useEffect(() => {
    void loadAuditLogs();
  }, [loadAuditLogs]);

  const handleVerifyChainNow = async () => {
    setVerifying(true);
    setError(null);
    try {
      const res = await apiClient.get<AuditChainVerification>('/audit/verify-chain');
      setChain(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setVerifying(false);
    }
  };

  const totalLogPages = Math.max(1, Math.ceil((logsPage?.total ?? 0) / 20));

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.AUDIT_READ} mode="page">
        {/* Header & Verify Chain CTA */}
        <div className="soc-card p-5 sm:p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-emerald-600 dark:text-emerald-400">
              <Scale className="w-3.5 h-3.5" />
              PCI-DSS v4.0 · ISO/IEC 27001:2022 · GDPR · TAMPER-EVIDENT SHA-256 LEDGER
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Regulatory Compliance &amp; Immutable Audit Trail
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              PostgreSQL append-only triggers (<code>NO UPDATE / DELETE / TRUNCATE</code>) with cryptographic SHA-256 hash chaining.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={verifying}
              onClick={() => void handleVerifyChainNow()}
              className="soc-btn-primary"
            >
              <ShieldCheck className="w-4 h-4" />
              {verifying ? 'Recomputing Hashes...' : 'Verify Cryptographic Chain'}
            </button>

            <button
              type="button"
              onClick={() => {
                void loadComplianceAndChain();
                void loadAuditLogs();
              }}
              className="soc-btn-secondary"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Cryptographic Chain Verification Status Banner */}
        {chain && (
          <div
            className={`p-4 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs ${
              chain.valid
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200'
                : 'border-red-500/40 bg-red-500/10 text-red-800 dark:text-red-200'
            }`}
          >
            <div className="flex items-center gap-3">
              {chain.valid ? (
                <CheckCircle2 className="w-6 h-6 text-emerald-500 shrink-0" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-red-500 shrink-0" />
              )}
              <div>
                <div className="font-mono font-black text-sm">
                  CRYPTOGRAPHIC CHAIN STATUS: {chain.valid ? 'VALID (TAMPER-FREE)' : 'BROKEN'}
                </div>
                <div className="text-[11px] opacity-90">
                  Algorithm: <code>{chain.algorithm}</code> · Verified{' '}
                  <strong>{chain.checked.toLocaleString()}</strong> append-only entries · Triggers:{' '}
                  <code>{chain.append_only_triggers.join(', ')}</code>
                </div>
              </div>
            </div>

            <div className="font-mono text-[11px] shrink-0">
              {chain.head_hash && (
                <div>Head SHA-256: {String(chain.head_hash).slice(0, 20)}…</div>
              )}
              <div>Verified: {formatUtcDateTime(chain.verified_at)}</div>
            </div>
          </div>
        )}

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Tab Switcher */}
        <div className="inline-flex rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-1 gap-1 text-xs">
          <button
            type="button"
            onClick={() => setTab('compliance')}
            className={`px-4 py-2 rounded-lg font-semibold transition ${
              tab === 'compliance'
                ? 'bg-blue-600 text-white'
                : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            1. Regulatory Compliance Matrix (PCI-DSS · ISO 27001 · GDPR)
          </button>
          <button
            type="button"
            onClick={() => setTab('logs')}
            className={`px-4 py-2 rounded-lg font-semibold transition ${
              tab === 'logs' ? 'bg-blue-600 text-white' : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            2. Immutable SHA-256 Audit Trail ({logsPage?.total ?? 0})
          </button>
        </div>

        {tab === 'compliance' && compliance && (
          <div className="space-y-6">
            {/* Live DB Evidence Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
              <div className="soc-card p-3.5">
                <div className="soc-label">Active RBAC Users</div>
                <div className="text-xl font-black text-slate-900 dark:text-white mt-1">
                  {compliance.live_evidence.active_users_count} /{' '}
                  {compliance.live_evidence.rbac_users_count}
                </div>
              </div>
              <div className="soc-card p-3.5">
                <div className="soc-label">MFA Enrolled</div>
                <div className="text-xl font-black text-blue-600 dark:text-blue-400 mt-1">
                  {compliance.live_evidence.mfa_enabled_users_count}
                </div>
              </div>
              <div className="soc-card p-3.5">
                <div className="soc-label">30d SLA Compliance</div>
                <div className="text-xl font-black text-emerald-600 dark:text-emerald-400 mt-1">
                  {(compliance.live_evidence.sla_compliance_rate * 100).toFixed(1)}%
                </div>
              </div>
              <div className="soc-card p-3.5">
                <div className="soc-label">Enforced IOCs</div>
                <div className="text-xl font-black text-purple-600 dark:text-purple-400 mt-1">
                  {compliance.live_evidence.active_iocs_count}
                </div>
              </div>
              <div className="soc-card p-3.5">
                <div className="soc-label">Audit Rows Checked</div>
                <div className="text-xl font-black text-emerald-600 dark:text-emerald-400 mt-1">
                  {compliance.live_evidence.audit_entries_checked}
                </div>
              </div>
            </div>

            {/* Framework Cards */}
            <div className="space-y-5">
              {compliance.frameworks.map((fw) => (
                <div key={fw.framework} className="soc-card p-5 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                    <h2 className="text-base font-bold text-slate-900 dark:text-white">
                      {fw.framework}
                    </h2>
                    <span className="px-2.5 py-0.5 rounded-full font-mono text-[11px] font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                      {fw.controls.length} CONTROLS VERIFIED
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {fw.controls.map((ctrl) => (
                      <div key={ctrl.id} className="soc-card-muted p-3.5 space-y-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono font-bold text-blue-600 dark:text-blue-400">
                            {ctrl.id}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                              ctrl.status === 'COMPLIANT'
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                                : 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30'
                            }`}
                          >
                            {ctrl.status}
                          </span>
                        </div>
                        <div className="font-bold text-slate-900 dark:text-white">
                          {ctrl.title}
                        </div>
                        <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                          {ctrl.evidence}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'logs' && (
          <div className="soc-card overflow-hidden">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-3">
              <input
                type="text"
                placeholder="Filter by action (e.g. AUTH_LOGIN_SUCCESS)..."
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPage(1);
                }}
                className="soc-input sm:w-64 font-mono"
              />
              <input
                type="text"
                placeholder="Filter by actor email..."
                value={userFilter}
                onChange={(e) => {
                  setUserFilter(e.target.value);
                  setPage(1);
                }}
                className="soc-input sm:w-64 font-mono"
              />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                    <th className="p-3">Timestamp (UTC)</th>
                    <th className="p-3">Actor &amp; IP</th>
                    <th className="p-3">Action &amp; Resource</th>
                    <th className="p-3">SHA-256 Chain Link (prev → entry)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                  {(logsPage?.items ?? []).map((row) => (
                    <tr key={String(row.id)} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                      <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                        {formatUtcDateTime(row.event_timestamp)}
                      </td>
                      <td className="p-3 font-mono">
                        <div className="font-semibold text-slate-900 dark:text-white">
                          {row.user_email}
                        </div>
                        <div className="text-[10px] text-slate-500">{row.client_ip ?? '—'}</div>
                      </td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-blue-500/15 text-blue-700 dark:text-blue-300">
                          {row.action}
                        </span>
                        <div className="font-mono text-[11px] text-slate-500 mt-0.5">
                          {row.resource}
                        </div>
                      </td>
                      <td className="p-3 font-mono text-[10px] text-slate-500">
                        <div className="flex items-center gap-1.5">
                          <span title={row.prev_hash}>{row.prev_hash.slice(0, 12)}…</span>
                          <Link2 className="w-3 h-3 text-emerald-500" />
                          <span
                            title={row.integrity_hash}
                            className="text-emerald-700 dark:text-emerald-400 font-bold"
                          >
                            {row.integrity_hash.slice(0, 14)}…
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
              <span className="text-slate-500">
                Page {page} of {totalLogPages} ({logsPage?.total ?? 0} immutable log entries)
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
                  disabled={page >= totalLogPages}
                  onClick={() => setPage((p) => Math.min(totalLogPages, p + 1))}
                  className="soc-btn-secondary px-2.5 py-1"
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        )}
      </RequirePermission>
    </div>
  );
}
