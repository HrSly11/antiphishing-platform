import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  FileDown,
  RefreshCw,
  Shield,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import KpiCard from '../components/dashboard/KpiCard';
import {
  formatShortDate,
  normalizeDashboardKpis,
  triggerBlobDownload,
} from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type { DashboardKpisRaw, NormalizedDashboardKpis } from '../types/domain';

const WINDOW_OPTIONS = [
  { days: 7, label: '7d' },
  { days: 14, label: '14d' },
  { days: 30, label: '30d' },
  { days: 90, label: '90d' },
];

const CHANNEL_COLORS = ['#3b82f6', '#f59e0b', '#8b5cf6', '#10b981'];

export default function DashboardPage() {
  const [windowDays, setWindowDays] = useState<number>(30);
  const [kpis, setKpis] = useState<NormalizedDashboardKpis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<boolean>(false);

  const loadKpis = useCallback(async (days: number) => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.get<DashboardKpisRaw>('/dashboard/kpis', {
        params: { window_days: days },
      });
      setKpis(normalizeDashboardKpis(res.data));
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadKpis(windowDays);
  }, [windowDays, loadKpis]);

  const handleQuickPdfExport = async () => {
    setExporting(true);
    try {
      const res = await apiClient.get('/reports/export/pdf', {
        params: { template: 'executive', window_days: windowDays },
        responseType: 'blob',
      });
      triggerBlobDownload(res.data as Blob, `SentinelBank_Executive_${windowDays}d.pdf`);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setExporting(false);
    }
  };

  const data = kpis ?? normalizeDashboardKpis(null);

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.DASHBOARD_READ} mode="page">
        {/* Header & Window Selector */}
        <div className="soc-card p-5 sm:p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-emerald-600 dark:text-emerald-400">
              <TrendingUp className="w-3.5 h-3.5" />
              SELECTIVE CQRS LIVE TELEMETRY · POSTGRESQL + PG_TRGM
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Analytical SOC Operations Dashboard
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Real-time multi-channel detection volumes, analyst confusion rates, gateway latency percentiles, and SLA compliance.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Window Selector */}
            <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 p-1">
              {WINDOW_OPTIONS.map((opt) => (
                <button
                  key={opt.days}
                  type="button"
                  onClick={() => setWindowDays(opt.days)}
                  className={`px-3 py-1 rounded-md text-xs font-mono font-semibold transition ${
                    windowDays === opt.days
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void loadKpis(windowDays)}
              disabled={loading}
              className="soc-btn-secondary"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            <button
              type="button"
              onClick={() => void handleQuickPdfExport()}
              disabled={exporting}
              className="soc-btn-primary"
            >
              <FileDown className="w-3.5 h-3.5" />
              {exporting ? 'Generating PDF...' : 'CISO PDF Brief'}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Row 1: Primary Detection & Verdict KPIs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title={`Total Analyzed (${windowDays}d)`}
            value={loading ? '...' : data.totalAnalyzed.toLocaleString()}
            subtitle={`Clean delivered: ${data.cleanCount.toLocaleString()}`}
            accent="blue"
            icon={<Activity className="w-4 h-4" />}
          />
          <KpiCard
            title="Malicious Quarantined"
            value={loading ? '...' : data.maliciousCount.toLocaleString()}
            subtitle="Blocked inline at MTA / SMS / QR / Web"
            accent="red"
            icon={<ShieldAlert className="w-4 h-4" />}
          />
          <KpiCard
            title="Suspicious Tagged"
            value={loading ? '...' : data.suspiciousCount.toLocaleString()}
            subtitle="Delivered with warning banner (35–69)"
            accent="amber"
            icon={<AlertTriangle className="w-4 h-4" />}
          />
          <KpiCard
            title="FP / FN Confusion Rates"
            value={
              loading
                ? '...'
                : `${data.falsePositiveRatePct}% / ${data.falseNegativeRatePct}%`
            }
            subtitle={`Accuracy: ${data.accuracyRatePct}% (${data.labeledCount} analyst-labeled)`}
            accent="emerald"
            icon={<CheckCircle2 className="w-4 h-4" />}
          />
        </div>

        {/* Row 2: Latency, Incidents SLA, IOCs & Dataset */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Gateway Latency Avg / P95"
            value={loading ? '...' : `${data.latencyAvgMs} / ${data.latencyP95Ms} ms`}
            subtitle="Target SLA: inline p95 < 350 ms"
            accent="emerald"
            icon={<Clock className="w-4 h-4" />}
          />
          <KpiCard
            title="Open Incidents / Overdue"
            value={loading ? '...' : `${data.openIncidents} / ${data.overdueIncidents}`}
            subtitle={
              data.overdueIncidents > 0
                ? 'Active SLA breach requires escalation'
                : 'All active cases within SLA window'
            }
            accent={data.overdueIncidents > 0 ? 'red' : 'amber'}
            icon={<AlertTriangle className="w-4 h-4" />}
          />
          <KpiCard
            title="SLA Compliance & MTTR"
            value={loading ? '...' : `${data.slaCompliancePct}%`}
            subtitle={`MTTR: ${data.mttrMinutes !== null ? `${data.mttrMinutes} min` : '—'} · MTTT: ${
              data.mtttMinutes !== null ? `${data.mtttMinutes} min` : '—'
            }`}
            accent="purple"
            icon={<Shield className="w-4 h-4" />}
          />
          <KpiCard
            title="Active IOCs & Dataset"
            value={
              loading
                ? '...'
                : `${data.activeIocs.toLocaleString()} / ${data.datasetSamples.toLocaleString()}`
            }
            subtitle="Enforced IOCs / Deduplicated OpenPhish+PhishTank"
            accent="blue"
            icon={<Database className="w-4 h-4" />}
          />
        </div>

        {/* Row 3: Charts — Daily UTC Trend + Channel Distribution */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8 soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Continuous UTC Daily Detections Trend ({windowDays} Days)
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Zero-filled daily series broken down by Clean, Suspicious, and Malicious verdicts
                </p>
              </div>
              <Link
                to="/verdicts"
                className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
              >
                Explore Verdicts →
              </Link>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.dailyTrend} margin={{ top: 10, right: 12, left: -15, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradMalicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="gradSuspicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="gradClean" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.25} />
                  <XAxis
                    dataKey="date"
                    tickFormatter={formatShortDate}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                  />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                  <Area
                    type="monotone"
                    dataKey="malicious"
                    name="Malicious (Quarantined)"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fill="url(#gradMalicious)"
                  />
                  <Area
                    type="monotone"
                    dataKey="suspicious"
                    name="Suspicious (Banner)"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    fill="url(#gradSuspicious)"
                  />
                  <Area
                    type="monotone"
                    dataKey="clean"
                    name="Clean (Delivered)"
                    stroke="#10b981"
                    strokeWidth={2}
                    fill="url(#gradClean)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="lg:col-span-4 soc-card p-5 space-y-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                Multi-Channel Distribution
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Inspected traffic across EMAIL, SMS, WEB, and QR vectors
              </p>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data.channelDistribution}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="48%"
                    innerRadius={52}
                    outerRadius={84}
                    paddingAngle={3}
                  >
                    {data.channelDistribution.map((entry, idx) => (
                      <Cell key={entry.name} fill={CHANNEL_COLORS[idx % CHANNEL_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '0.5rem',
                      fontSize: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Row 4: Top Attacker Domains & Top Originating Attacker IPs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Top Hostile Sender &amp; Lure Domains
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Aggregated from malicious and suspicious verdicts
                </p>
              </div>
              <Link
                to="/iocs"
                className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
              >
                Manage IOCs →
              </Link>
            </div>

            <div className="h-64 w-full">
              {data.topDomains.length === 0 ? (
                <div className="h-full flex items-center justify-center text-xs text-slate-500">
                  No hostile domains recorded in selected window.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={data.topDomains}
                    layout="vertical"
                    margin={{ top: 4, right: 20, left: 20, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                    <YAxis
                      type="category"
                      dataKey="domain"
                      width={155}
                      tick={{ fontSize: 10, fill: '#94a3b8' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '0.5rem',
                        fontSize: '12px',
                        color: '#f8fafc',
                      }}
                    />
                    <Bar dataKey="count" name="Detections" fill="#ef4444" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Top Originating Attacker IPs
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Extracted from Received / Originating-IP headers &amp; URL lures
                </p>
              </div>
              <Link
                to="/threat-hunting"
                className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
              >
                Hunt Infrastructure →
              </Link>
            </div>

            <div className="h-64 w-full">
              {data.topIps.length === 0 ? (
                <div className="h-full flex items-center justify-center text-xs text-slate-500">
                  No hostile IPv4 relays recorded in selected window.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={data.topIps}
                    layout="vertical"
                    margin={{ top: 4, right: 20, left: 10, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                    <YAxis
                      type="category"
                      dataKey="ip"
                      width={120}
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '0.5rem',
                        fontSize: '12px',
                        color: '#f8fafc',
                      }}
                    />
                    <Bar dataKey="count" name="Hits" fill="#f59e0b" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>
      </RequirePermission>
    </div>
  );
}
