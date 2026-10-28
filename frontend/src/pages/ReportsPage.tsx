import { useCallback, useEffect, useState } from 'react';
import {
  CalendarClock,
  FileSpreadsheet,
  FileText,
  FileType2,
  Play,
  Plus,
  RefreshCw,
  Trash2,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import { formatUtcDateTime, triggerBlobDownload } from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type { ScheduleItem } from '../types/domain';

type ReportTemplate = 'executive' | 'operational' | 'compliance';
type ReportFormat = 'pdf' | 'docx' | 'xlsx';

export default function ReportsPage() {
  const [template, setTemplate] = useState<ReportTemplate>('executive');
  const [windowDays, setWindowDays] = useState<number>(30);
  const [verdict, setVerdict] = useState<string>('');
  const [channel, setChannel] = useState<string>('');
  const [recipientEmail, setRecipientEmail] = useState<string>('');
  const [downloadingFmt, setDownloadingFmt] = useState<ReportFormat | null>(null);

  const [schedules, setSchedules] = useState<ScheduleItem[]>([]);
  const [loadingSchedules, setLoadingSchedules] = useState(true);
  const [runningDue, setRunningDue] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);

  const [schedForm, setSchedForm] = useState({
    name: 'Weekly Executive CISO Phishing Telemetry',
    report_format: 'pdf' as ReportFormat,
    frequency: 'WEEKLY' as 'DAILY' | 'WEEKLY',
    recipientsText: 'ciso@bancocentral.com, auditor@bancocentral.com',
    template: 'executive' as ReportTemplate,
    window_days: 7,
  });
  const [creatingSched, setCreatingSched] = useState(false);

  const loadSchedules = useCallback(async () => {
    setLoadingSchedules(true);
    try {
      const res = await apiClient.get<ScheduleItem[]>('/reports/schedules');
      setSchedules(res.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoadingSchedules(false);
    }
  }, []);

  useEffect(() => {
    void loadSchedules();
  }, [loadSchedules]);

  const handleDownload = async (fmt: ReportFormat) => {
    setDownloadingFmt(fmt);
    setError(null);
    setBanner(null);
    try {
      const payload: Record<string, unknown> = {
        report_format: fmt,
        template,
        window_days: windowDays,
      };
      if (verdict) payload.verdict = verdict;
      if (channel) payload.channel = channel;
      if (recipientEmail.trim()) payload.recipient_email = recipientEmail.trim();

      const res = await apiClient.post('/reports/generate', payload, {
        responseType: 'blob',
      });

      const contentDisp = String(res.headers['content-disposition'] ?? '');
      const match = contentDisp.match(/filename="?([^"]+)"?/i);
      const filename =
        match?.[1] ?? `SentinelBank_${template}_${windowDays}d.${fmt}`;

      triggerBlobDownload(res.data as Blob, filename);
      setBanner(
        `Generated and downloaded ${filename} (${((res.data as Blob).size / 1024).toFixed(1)} KB).`,
      );
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setDownloadingFmt(null);
    }
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingSched(true);
    setError(null);
    setBanner(null);
    try {
      const recipients = schedForm.recipientsText
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean);
      await apiClient.post('/reports/schedules', {
        name: schedForm.name,
        report_format: schedForm.report_format,
        frequency: schedForm.frequency,
        recipients,
        template: schedForm.template,
        window_days: schedForm.window_days,
      });
      setBanner(`Created recurring ${schedForm.frequency} schedule '${schedForm.name}'.`);
      await loadSchedules();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setCreatingSched(false);
    }
  };

  const handleDeleteSchedule = async (id: string, name: string) => {
    setError(null);
    try {
      await apiClient.delete(`/reports/schedules/${id}`);
      setBanner(`Deleted report schedule '${name}'.`);
      await loadSchedules();
    } catch (err) {
      setError(extractApiError(err));
    }
  };

  const handleRunDue = async () => {
    setRunningDue(true);
    setError(null);
    setBanner(null);
    try {
      const res = await apiClient.post<{ executed?: number; count?: number }>(
        '/reports/schedules/run-due?force_all=true',
      );
      const ran = res.data.executed ?? res.data.count ?? schedules.length;
      setBanner(`Executed ${ran} active report schedule(s) and updated delivery status.`);
      await loadSchedules();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setRunningDue(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.REPORTS_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
              <FileSpreadsheet className="w-3.5 h-3.5" />
              MULTI-FORMAT TELEMETRY EXPORTS (PDF · DOCX · XLSX) &amp; CRON SCHEDULER
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Executive, Operational &amp; Compliance Reports
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Generate real binary PDF, Word, and Excel reports from live PostgreSQL telemetry or automate recurring n8n/SMTP schedules.
            </p>
          </div>

          <button type="button" onClick={() => void loadSchedules()} className="soc-btn-secondary">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingSchedules ? 'animate-spin' : ''}`} />
            Refresh
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

        {/* Section 1: On-Demand Binary Report Builder */}
        <div className="soc-card p-5 sm:p-6 space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">
              On-Demand Multi-Format Report Builder
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Configure report scope and click any format button below to stream a binary file download.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
            <div>
              <label className="soc-label mb-1">Report Template</label>
              <select
                value={template}
                onChange={(e) => setTemplate(e.target.value as ReportTemplate)}
                className="soc-input"
              >
                <option value="executive">Executive CISO Summary</option>
                <option value="operational">SOC Operational Detail</option>
                <option value="compliance">PCI-DSS &amp; ISO Compliance</option>
              </select>
            </div>

            <div>
              <label className="soc-label mb-1">Time Window</label>
              <select
                value={String(windowDays)}
                onChange={(e) => setWindowDays(Number(e.target.value))}
                className="soc-input font-mono"
              >
                <option value="7">Last 7 Days</option>
                <option value="14">Last 14 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
              </select>
            </div>

            <div>
              <label className="soc-label mb-1">Verdict Filter</label>
              <select
                value={verdict}
                onChange={(e) => setVerdict(e.target.value)}
                className="soc-input"
              >
                <option value="">All Verdicts</option>
                <option value="MALICIOUS">MALICIOUS Only</option>
                <option value="SUSPICIOUS">SUSPICIOUS Only</option>
                <option value="CLEAN">CLEAN Only</option>
              </select>
            </div>

            <div>
              <label className="soc-label mb-1">Channel Filter</label>
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
            </div>

            <div>
              <label className="soc-label mb-1">Optional SMTP Delivery</label>
              <input
                type="email"
                placeholder="ciso@bancocentral.com"
                value={recipientEmail}
                onChange={(e) => setRecipientEmail(e.target.value)}
                className="soc-input font-mono"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              disabled={downloadingFmt !== null}
              onClick={() => void handleDownload('pdf')}
              className="soc-btn-primary"
            >
              <FileText className="w-4 h-4" />
              {downloadingFmt === 'pdf' ? 'Rendering PDF...' : 'Download PDF (.pdf)'}
            </button>

            <button
              type="button"
              disabled={downloadingFmt !== null}
              onClick={() => void handleDownload('docx')}
              className="soc-btn-secondary border-blue-500/40 text-blue-700 dark:text-blue-300"
            >
              <FileType2 className="w-4 h-4" />
              {downloadingFmt === 'docx' ? 'Rendering Word...' : 'Download Word (.docx)'}
            </button>

            <button
              type="button"
              disabled={downloadingFmt !== null}
              onClick={() => void handleDownload('xlsx')}
              className="soc-btn-secondary border-emerald-500/40 text-emerald-700 dark:text-emerald-300"
            >
              <FileSpreadsheet className="w-4 h-4" />
              {downloadingFmt === 'xlsx' ? 'Rendering Excel...' : 'Download Excel (.xlsx)'}
            </button>
          </div>
        </div>

        {/* Section 2: Scheduled Automated Reports */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <form
            onSubmit={handleCreateSchedule}
            className="lg:col-span-4 soc-card p-5 space-y-3 text-xs"
          >
            <div className="flex items-center gap-2">
              <CalendarClock className="w-4 h-4 text-blue-500" />
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                New Automated Schedule
              </h2>
            </div>

            <div>
              <label className="soc-label mb-1">Schedule Name</label>
              <input
                type="text"
                required
                value={schedForm.name}
                onChange={(e) => setSchedForm({ ...schedForm, name: e.target.value })}
                className="soc-input"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="soc-label mb-1">Format</label>
                <select
                  value={schedForm.report_format}
                  onChange={(e) =>
                    setSchedForm({
                      ...schedForm,
                      report_format: e.target.value as ReportFormat,
                    })
                  }
                  className="soc-input font-mono"
                >
                  <option value="pdf">PDF (.pdf)</option>
                  <option value="docx">Word (.docx)</option>
                  <option value="xlsx">Excel (.xlsx)</option>
                </select>
              </div>
              <div>
                <label className="soc-label mb-1">Frequency</label>
                <select
                  value={schedForm.frequency}
                  onChange={(e) =>
                    setSchedForm({
                      ...schedForm,
                      frequency: e.target.value as 'DAILY' | 'WEEKLY',
                    })
                  }
                  className="soc-input font-mono"
                >
                  <option value="DAILY">DAILY</option>
                  <option value="WEEKLY">WEEKLY</option>
                </select>
              </div>
            </div>

            <div>
              <label className="soc-label mb-1">Template</label>
              <select
                value={schedForm.template}
                onChange={(e) =>
                  setSchedForm({
                    ...schedForm,
                    template: e.target.value as ReportTemplate,
                  })
                }
                className="soc-input"
              >
                <option value="executive">executive</option>
                <option value="operational">operational</option>
                <option value="compliance">compliance</option>
              </select>
            </div>

            <div>
              <label className="soc-label mb-1">Comma-Separated Recipients</label>
              <input
                type="text"
                required
                value={schedForm.recipientsText}
                onChange={(e) =>
                  setSchedForm({ ...schedForm, recipientsText: e.target.value })
                }
                className="soc-input font-mono"
              />
            </div>

            <RequirePermission permission={PERMISSIONS.REPORTS_MANAGE} mode="disable">
              <button type="submit" disabled={creatingSched} className="soc-btn-primary w-full">
                <Plus className="w-4 h-4" />
                {creatingSched ? 'Saving...' : 'Create Schedule'}
              </button>
            </RequirePermission>
          </form>

          <div className="lg:col-span-8 soc-card overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2 flex-wrap">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Configured Recurring Schedules ({schedules.length})
                </h2>
                <p className="text-[11px] text-slate-500">
                  Executed automatically by the background scheduler or n8n daily cron workflow
                </p>
              </div>
              <RequirePermission permission={PERMISSIONS.REPORTS_MANAGE} mode="disable">
                <button
                  type="button"
                  disabled={runningDue}
                  onClick={() => void handleRunDue()}
                  className="soc-btn-secondary"
                >
                  <Play className="w-3.5 h-3.5" />
                  {runningDue ? 'Running...' : 'Run Due Schedules'}
                </button>
              </RequirePermission>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                    <th className="p-3.5">Schedule / Template</th>
                    <th className="p-3.5">Format / Freq</th>
                    <th className="p-3.5">Recipients</th>
                    <th className="p-3.5">Last / Next Run</th>
                    <th className="p-3.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                  {loadingSchedules ? (
                    <tr>
                      <td colSpan={5} className="p-8 text-center text-slate-500">
                        Loading schedules...
                      </td>
                    </tr>
                  ) : schedules.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-8 text-center text-slate-500">
                        No recurring report schedules configured.
                      </td>
                    </tr>
                  ) : (
                    schedules.map((s) => (
                      <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                        <td className="p-3.5">
                          <div className="font-bold text-slate-900 dark:text-white">{s.name}</div>
                          <div className="text-[11px] font-mono text-slate-500">
                            template={s.template} · {s.last_status ?? 'Pending first run'}
                          </div>
                        </td>
                        <td className="p-3.5 font-mono">
                          <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-700 dark:text-blue-300 font-bold uppercase text-[10px]">
                            {s.report_format}
                          </span>{' '}
                          <span className="text-[11px] text-slate-500">{s.frequency}</span>
                        </td>
                        <td className="p-3.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                          {s.recipients.join(', ')}
                        </td>
                        <td className="p-3.5 font-mono text-[10px] text-slate-500">
                          <div>Last: {formatUtcDateTime(s.last_run_at)}</div>
                          <div>Next: {formatUtcDateTime(s.next_run_at)}</div>
                        </td>
                        <td className="p-3.5 text-right">
                          <RequirePermission permission={PERMISSIONS.REPORTS_MANAGE} mode="disable">
                            <button
                              type="button"
                              onClick={() => void handleDeleteSchedule(s.id, s.name)}
                              className="soc-btn-danger px-2 py-1 text-[10px]"
                            >
                              <Trash2 className="w-3 h-3" /> Delete
                            </button>
                          </RequirePermission>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </RequirePermission>
    </div>
  );
}
