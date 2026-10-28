import { useCallback, useEffect, useState } from 'react';
import {
  Flag,
  MailOpen,
  MousePointerClick,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  Target,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import KpiCard from '../components/dashboard/KpiCard';
import { PERMISSIONS } from '../lib/permissions';
import type {
  ChannelType,
  SimulationAggregateMetrics,
  SimulationCampaign,
} from '../types/domain';

export default function SimulationPage() {
  const [metrics, setMetrics] = useState<SimulationAggregateMetrics | null>(null);
  const [campaigns, setCampaigns] = useState<SimulationCampaign[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('');
  const [employeeEmail, setEmployeeEmail] = useState('tesoreria.operador01@bancocentral.com');
  const [department, setDepartment] = useState('Finance & Treasury');

  const [campaignForm, setCampaignForm] = useState({
    name: 'Q4 Executive BEC & Wire Authorization Drill',
    channel: 'EMAIL' as ChannelType,
    template_subject: 'URGENTE: Aprobación de transferencia interbancaria confidencial',
    lure_type: 'BEC_WIRE_FRAUD',
    target_department: 'Finance & Treasury',
    total_targets: 30,
  });

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);

  const loadSimulationData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [mRes, cRes] = await Promise.all([
        apiClient.get<SimulationAggregateMetrics>('/simulation/metrics'),
        apiClient.get<SimulationCampaign[]>('/simulation/campaigns'),
      ]);
      setMetrics(mRes.data);
      setCampaigns(cRes.data);
      if (!selectedCampaignId && cRes.data.length > 0) {
        setSelectedCampaignId(cRes.data[0].id);
        setDepartment(cRes.data[0].target_department);
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [selectedCampaignId]);

  useEffect(() => {
    void loadSimulationData();
  }, [loadSimulationData]);

  const handleCreateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setBanner(null);
    try {
      const res = await apiClient.post<SimulationCampaign>(
        '/simulation/campaigns',
        campaignForm,
      );
      setBanner(`Launched awareness drill '${res.data.name}'.`);
      setSelectedCampaignId(res.data.id);
      await loadSimulationData();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const recordTelemetryEvent = async (
    eventType: 'SENT' | 'OPENED' | 'CLICKED' | 'REPORTED',
  ) => {
    if (!selectedCampaignId || !employeeEmail.trim()) return;
    setBusy(true);
    setError(null);
    setBanner(null);
    try {
      await apiClient.post(`/simulation/campaigns/${selectedCampaignId}/events`, {
        employee_email: employeeEmail.trim(),
        event_type: eventType,
        department,
      });
      setBanner(
        `Recorded ${eventType} telemetry event for ${employeeEmail.trim()} — campaign rates recomputed live.`,
      );
      await loadSimulationData();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const fmtPct = (v?: number) => {
    const num = Number(v ?? 0);
    return `${(num <= 1 && num > 0 ? num * 100 : num).toFixed(1)}%`;
  };

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.DETECTION_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-amber-600 dark:text-amber-400">
              <Target className="w-3.5 h-3.5" />
              PCI-DSS v4.0 REQ 12.6 · EMPLOYEE PHISHING AWARENESS &amp; HUMAN RISK DRILLS
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Phishing Simulation &amp; Employee Awareness Telemetry
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Launch controlled multi-channel phishing drills and measure click susceptibility vs. proactive employee reporting.
            </p>
          </div>

          <button type="button" onClick={() => void loadSimulationData()} className="soc-btn-secondary">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh KPIs
          </button>
        </div>

        {banner && (
          <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-700 dark:text-emerald-300">
            {banner}
          </div>
        )}
        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Awareness KPIs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Overall Click Susceptibility"
            value={loading ? '...' : fmtPct(metrics?.overall_click_rate)}
            subtitle={`${metrics?.total_clicked ?? 0} clicked of ${metrics?.total_sent ?? 0} sent`}
            accent="red"
            icon={<MousePointerClick className="w-4 h-4" />}
          />
          <KpiCard
            title="Simulation Report Rate"
            value={loading ? '...' : fmtPct(metrics?.overall_report_rate)}
            subtitle={`${metrics?.total_reported ?? 0} proactive employee reports`}
            accent="emerald"
            icon={<Flag className="w-4 h-4" />}
          />
          <KpiCard
            title="Human Compromise Risk"
            value={loading ? '...' : (metrics?.overall_compromise_risk ?? 'LOW')}
            subtitle={`Active drills: ${metrics?.active_campaigns ?? 0} / ${metrics?.total_campaigns ?? 0}`}
            accent="amber"
            icon={<ShieldAlert className="w-4 h-4" />}
          />
          <KpiCard
            title="Real 'Reportar Phishing' Intake"
            value={loading ? '...' : (metrics?.employee_reported_phishing_count ?? 0)}
            subtitle="Live employee submissions to SOC gateway"
            accent="blue"
            icon={<Send className="w-4 h-4" />}
          />
        </div>

        {/* Interactive Simulation Runner + Create Campaign */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Interactive Simulation Runner */}
          <div className="lg:col-span-7 soc-card p-5 space-y-4 text-xs">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                Interactive Employee Interaction Runner
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Simulate an employee receiving, opening, clicking, or reporting a campaign lure and watch PostgreSQL recompute department &amp; campaign KPIs in real time.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-3">
                <label className="soc-label mb-1">Target Campaign</label>
                <select
                  value={selectedCampaignId}
                  onChange={(e) => {
                    setSelectedCampaignId(e.target.value);
                    const found = campaigns.find((c) => c.id === e.target.value);
                    if (found) setDepartment(found.target_department);
                  }}
                  className="soc-input"
                >
                  {campaigns.map((c) => (
                    <option key={c.id} value={c.id}>
                      [{c.channel}] {c.name} ({c.target_department})
                    </option>
                  ))}
                </select>
              </div>

              <div className="sm:col-span-2">
                <label className="soc-label mb-1">Simulated Employee Email</label>
                <input
                  type="email"
                  value={employeeEmail}
                  onChange={(e) => setEmployeeEmail(e.target.value)}
                  className="soc-input font-mono"
                />
              </div>

              <div>
                <label className="soc-label mb-1">Department</label>
                <input
                  type="text"
                  value={department}
                  onChange={(e) => setDepartment(e.target.value)}
                  className="soc-input"
                />
              </div>
            </div>

            <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                <button
                  type="button"
                  disabled={busy || !selectedCampaignId}
                  onClick={() => void recordTelemetryEvent('SENT')}
                  className="soc-btn-secondary"
                >
                  <Send className="w-3.5 h-3.5" /> 1. SENT
                </button>
                <button
                  type="button"
                  disabled={busy || !selectedCampaignId}
                  onClick={() => void recordTelemetryEvent('OPENED')}
                  className="soc-btn-secondary"
                >
                  <MailOpen className="w-3.5 h-3.5" /> 2. OPENED
                </button>
                <button
                  type="button"
                  disabled={busy || !selectedCampaignId}
                  onClick={() => void recordTelemetryEvent('CLICKED')}
                  className="soc-btn-danger"
                >
                  <MousePointerClick className="w-3.5 h-3.5" /> 3. CLICKED
                </button>
                <button
                  type="button"
                  disabled={busy || !selectedCampaignId}
                  onClick={() => void recordTelemetryEvent('REPORTED')}
                  className="soc-btn-primary"
                >
                  <Flag className="w-3.5 h-3.5" /> 4. REPORTED
                </button>
              </div>
            </RequirePermission>

            {/* Campaigns Table */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
              <div className="soc-label">Active Simulation Campaigns ({campaigns.length})</div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                      <th className="p-2.5">Campaign / Dept</th>
                      <th className="p-2.5">Sent / Open / Click / Rep</th>
                      <th className="p-2.5">Click %</th>
                      <th className="p-2.5">Report %</th>
                      <th className="p-2.5">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                    {campaigns.map((c) => (
                      <tr key={c.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                        <td className="p-2.5">
                          <div className="font-bold text-slate-900 dark:text-white">{c.name}</div>
                          <div className="text-[10px] font-mono text-slate-500">
                            {c.channel} · {c.target_department}
                          </div>
                        </td>
                        <td className="p-2.5 font-mono">
                          {c.sent_count} / {c.opened_count} / {c.clicked_count} / {c.reported_count}
                        </td>
                        <td className="p-2.5 font-mono text-red-600 dark:text-red-400 font-bold">
                          {fmtPct(c.click_rate)}
                        </td>
                        <td className="p-2.5 font-mono text-emerald-600 dark:text-emerald-400 font-bold">
                          {fmtPct(c.report_rate)}
                        </td>
                        <td className="p-2.5 font-mono font-bold">{c.compromise_risk}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Launch New Campaign Form */}
          <form
            onSubmit={handleCreateCampaign}
            className="lg:col-span-5 soc-card p-5 space-y-3 text-xs"
          >
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">
              Launch New Awareness Campaign
            </h2>

            <div>
              <label className="soc-label mb-1">Campaign Name</label>
              <input
                type="text"
                required
                value={campaignForm.name}
                onChange={(e) => setCampaignForm({ ...campaignForm, name: e.target.value })}
                className="soc-input"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="soc-label mb-1">Channel</label>
                <select
                  value={campaignForm.channel}
                  onChange={(e) =>
                    setCampaignForm({
                      ...campaignForm,
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
                <label className="soc-label mb-1">Lure Archetype</label>
                <select
                  value={campaignForm.lure_type}
                  onChange={(e) =>
                    setCampaignForm({ ...campaignForm, lure_type: e.target.value })
                  }
                  className="soc-input font-mono"
                >
                  <option value="CREDENTIAL_HARVEST">CREDENTIAL_HARVEST</option>
                  <option value="BEC_WIRE_FRAUD">BEC_WIRE_FRAUD</option>
                  <option value="QUISHING_OAUTH">QUISHING_OAUTH</option>
                  <option value="SMISHING_OTP">SMISHING_OTP</option>
                </select>
              </div>
            </div>

            <div>
              <label className="soc-label mb-1">Template Subject / Lure Prompt</label>
              <input
                type="text"
                required
                value={campaignForm.template_subject}
                onChange={(e) =>
                  setCampaignForm({ ...campaignForm, template_subject: e.target.value })
                }
                className="soc-input"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="soc-label mb-1">Target Department</label>
                <input
                  type="text"
                  required
                  value={campaignForm.target_department}
                  onChange={(e) =>
                    setCampaignForm({ ...campaignForm, target_department: e.target.value })
                  }
                  className="soc-input"
                />
              </div>
              <div>
                <label className="soc-label mb-1">Target Headcount</label>
                <input
                  type="number"
                  min={1}
                  max={100000}
                  value={campaignForm.total_targets}
                  onChange={(e) =>
                    setCampaignForm({
                      ...campaignForm,
                      total_targets: Number(e.target.value),
                    })
                  }
                  className="soc-input font-mono"
                />
              </div>
            </div>

            <RequirePermission permission={PERMISSIONS.INCIDENTS_WRITE} mode="disable">
              <button type="submit" disabled={busy} className="soc-btn-primary w-full">
                <Plus className="w-4 h-4" />
                {busy ? 'Launching...' : 'Launch Simulation Drill'}
              </button>
            </RequirePermission>
          </form>
        </div>
      </RequirePermission>
    </div>
  );
}
