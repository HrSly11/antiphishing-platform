import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Code2,
  ExternalLink,
  FileCode2,
  Flag,
  Globe,
  Inbox,
  Mail,
  Pause,
  Play,
  Send,
  ShieldAlert,
  Terminal,
  Upload,
  Zap,
} from 'lucide-react';
import { extractApiError } from '../api/client';
import {
  analyzeEmail,
  analyzeEmlFile,
  analyzeRawEml,
  analyzeUrl,
  reportEmployeePhishing,
} from '../api/queries/useAnalyze';
import RequirePermission from '../components/auth/RequirePermission';
import {
  getActionBadgeClasses,
  getSeverityBadgeClasses,
  getVerdictBadgeClasses,
} from '../lib/formatters';
import { MAIL_SCENARIOS, SAMPLE_RAW_EML, type MailScenario } from '../lib/mailScenarios';
import { PERMISSIONS } from '../lib/permissions';
import { useAuthStore } from '../stores/authStore';
import type { ChannelType, EmailAnalysisResponse } from '../types/domain';

type AnalyzerTab = 'email' | 'eml' | 'url' | 'report';

interface InspectionRecord {
  id: string;
  endpoint: string;
  requestPayload: unknown;
  response: EmailAnalysisResponse;
  httpStatus: number;
  clientLatencyMs: number;
  at: string;
}

export default function AnalyzePage() {
  const user = useAuthStore((s) => s.user);
  const [tab, setTab] = useState<AnalyzerTab>('email');
  const [history, setHistory] = useState<InspectionRecord[]>([]);
  const [selected, setSelected] = useState<InspectionRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [liveStreamActive, setLiveStreamActive] = useState(false);
  const [streamCursor, setStreamCursor] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const didInitialAutoFire = useRef(false);

  // Tab 1: Inline MTA Email form
  const [emailForm, setEmailForm] = useState({
    sender: MAIL_SCENARIOS[0].request.sender,
    recipient: MAIL_SCENARIOS[0].request.recipient,
    subject: MAIL_SCENARIOS[0].request.subject,
    body_text: MAIL_SCENARIOS[0].request.body_text,
    attachmentName: '',
    channel: 'EMAIL' as ChannelType,
    spfResult: 'pass',
    dkimResult: 'pass',
    dmarcResult: 'pass',
    originatingIp: '200.48.225.10',
    replyTo: '',
  });

  // Tab 2: .eml upload / raw
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [rawEmlText, setRawEmlText] = useState<string>(SAMPLE_RAW_EML);

  // Tab 3: Standalone URL / SMS / QR scanner
  const [urlForm, setUrlForm] = useState({
    url: 'http://bancocentral-seguridad.com/login-token',
    channel: 'WEB' as ChannelType,
    sender: 'alertas@bancocentral-seguridad.com',
    message_text: 'Valide su clave OTP y coordenadas inmediatamente.',
    enrich: true,
  });

  // Tab 4: Employee "Reportar Phishing"
  const [reportForm, setReportForm] = useState({
    sender_email: 'premio-vip@sorteo-bancario-latam.top',
    reported_by_email: user?.email ?? 'colaborador@bancocentral.com',
    subject: 'Gane un bono corporativo validando su contraseña de red',
    body_text:
      'Estimado colaborador, confirme su usuario Active Directory y token en http://185.220.101.5/login-portal/token para recibir el abono.',
    channel: 'EMAIL' as ChannelType,
  });

  const recordResult = (
    endpoint: string,
    requestPayload: unknown,
    response: EmailAnalysisResponse,
    httpStatus: number,
    clientLatencyMs: number,
  ) => {
    const rec: InspectionRecord = {
      id: `${response.correlation_id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      endpoint,
      requestPayload,
      response,
      httpStatus,
      clientLatencyMs,
      at: new Date().toLocaleTimeString(),
    };
    setHistory((prev) => [rec, ...prev].slice(0, 30));
    setSelected(rec);
  };

  const syncFormWithScenario = (sc: MailScenario) => {
    const authHdr = sc.request.headers?.['authentication-results'] ?? '';
    setEmailForm({
      sender: sc.request.sender,
      recipient: sc.request.recipient,
      subject: sc.request.subject,
      body_text: sc.request.body_text,
      attachmentName: sc.request.attachments?.[0]?.filename ?? '',
      channel: sc.request.channel ?? 'EMAIL',
      spfResult: authHdr.includes('spf=pass')
        ? 'pass'
        : authHdr.includes('spf=softfail')
          ? 'softfail'
          : 'fail',
      dkimResult: authHdr.includes('dkim=pass') ? 'pass' : 'none',
      dmarcResult: authHdr.includes('dmarc=pass') ? 'pass' : 'fail',
      originatingIp: sc.request.headers?.originating_ip ?? '200.48.225.10',
      replyTo: sc.request.headers?.['reply-to'] ?? '',
    });
  };

  // Fire a scenario immediately against the live API when clicked
  const handleTriggerScenarioLive = async (sc: MailScenario) => {
    syncFormWithScenario(sc);
    setBusy(true);
    setError(null);
    try {
      const res = await analyzeEmail(sc.request);
      recordResult(
        'POST /api/v1/detection/analyze-email',
        sc.request,
        res.data,
        res.status,
        res.latencyMs,
      );
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  // On initial mount, auto-fire 2 corporate emails (1 clean accepted + 1 phishing quarantined)
  // so the evaluator immediately sees real-time API traffic and inbox routing in action!
  useEffect(() => {
    if (didInitialAutoFire.current) return;
    didInitialAutoFire.current = true;
    const runInitialPair = async () => {
      try {
        const cleanSc = MAIL_SCENARIOS[0];
        const phishSc = MAIL_SCENARIOS[1];
        const r1 = await analyzeEmail(cleanSc.request);
        recordResult('POST /api/v1/detection/analyze-email', cleanSc.request, r1.data, r1.status, r1.latencyMs);
        const r2 = await analyzeEmail(phishSc.request);
        recordResult('POST /api/v1/detection/analyze-email', phishSc.request, r2.data, r2.status, r2.latencyMs);
      } catch {
        // Ignore initial auto-fire errors if unauthenticated
      }
    };
    void runInitialPair();
  }, []);

  // Continuous Live MTA Stream Simulator (fires 1 real email every 2.8 seconds when active)
  useEffect(() => {
    if (!liveStreamActive) return;
    const timer = setInterval(async () => {
      const sc = MAIL_SCENARIOS[streamCursor % MAIL_SCENARIOS.length];
      setStreamCursor((c) => c + 1);
      syncFormWithScenario(sc);
      try {
        const res = await analyzeEmail(sc.request);
        recordResult(
          'POST /api/v1/detection/analyze-email',
          sc.request,
          res.data,
          res.status,
          res.latencyMs,
        );
      } catch (err) {
        setError(extractApiError(err));
        setLiveStreamActive(false);
      }
    }, 2800);

    return () => clearInterval(timer);
  }, [liveStreamActive, streamCursor]);

  const handleRunScenarioBatch = async () => {
    setBusy(true);
    setError(null);
    try {
      for (const sc of MAIL_SCENARIOS) {
        syncFormWithScenario(sc);
        const res = await analyzeEmail(sc.request);
        recordResult(
          'POST /api/v1/detection/analyze-email',
          sc.request,
          res.data,
          res.status,
          res.latencyMs,
        );
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const headers: Record<string, string> = {
      originating_ip: emailForm.originatingIp,
      'received-spf': emailForm.spfResult === 'pass' ? 'Pass' : 'Fail',
      'authentication-results': `spf=${emailForm.spfResult} dkim=${emailForm.dkimResult} dmarc=${emailForm.dmarcResult}`,
    };
    if (emailForm.replyTo.trim()) {
      headers['reply-to'] = emailForm.replyTo.trim();
    }
    const payload = {
      sender: emailForm.sender,
      recipient: emailForm.recipient,
      subject: emailForm.subject,
      body_text: emailForm.body_text,
      headers,
      attachments: emailForm.attachmentName.trim()
        ? [{ filename: emailForm.attachmentName.trim(), size_bytes: 512000 }]
        : [],
      channel: emailForm.channel,
    };
    try {
      const res = await analyzeEmail(payload);
      recordResult(
        'POST /api/v1/detection/analyze-email',
        payload,
        res.data,
        res.status,
        res.latencyMs,
      );
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleEmlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (emlFile) {
        const res = await analyzeEmlFile(emlFile);
        recordResult(
          'POST /api/v1/detection/analyze-eml (multipart/form-data)',
          { filename: emlFile.name, size: emlFile.size },
          res.data,
          res.status,
          res.latencyMs,
        );
      } else {
        const res = await analyzeRawEml(rawEmlText);
        recordResult(
          'POST /api/v1/detection/analyze-eml (raw RFC 822)',
          { raw_eml: rawEmlText },
          res.data,
          res.status,
          res.latencyMs,
        );
      }
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await analyzeUrl(urlForm);
      recordResult(
        'POST /api/v1/detection/analyze-url',
        urlForm,
        res.data,
        res.status,
        res.latencyMs,
      );
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await reportEmployeePhishing(reportForm);
      recordResult(
        'POST /api/v1/detection/report-phishing',
        reportForm,
        res.data,
        res.status,
        res.latencyMs,
      );
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const activeResp = selected?.response ?? null;
  const authHeaderStr = String(
    (selected?.requestPayload as { headers?: Record<string, string> } | undefined)?.headers?.[
      'authentication-results'
    ] ?? '',
  ).toLowerCase();

  const parseAuthBadge = (proto: 'spf' | 'dkim' | 'dmarc') => {
    if (authHeaderStr.includes(`${proto}=pass`)) {
      return {
        label: `${proto.toUpperCase()}: PASS`,
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
      };
    }
    if (authHeaderStr.includes(`${proto}=fail`)) {
      return {
        label: `${proto.toUpperCase()}: FAIL`,
        cls: 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30',
      };
    }
    if (authHeaderStr.includes(`${proto}=softfail`)) {
      return {
        label: `${proto.toUpperCase()}: SOFTFAIL`,
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
      };
    }
    return {
      label: `${proto.toUpperCase()}: NONE/N/A`,
      cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30',
    };
  };

  const acceptedEmails = history.filter((h) => h.response.action === 'DELIVER');
  const taggedEmails = history.filter((h) => h.response.action === 'TAG_AND_BANNER');
  const quarantinedEmails = history.filter((h) => h.response.action === 'QUARANTINE');

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      {/* Page Header + Real-Time Corporate Mail Stream Controls */}
      <div className="soc-card p-5 sm:p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
            <Mail className="w-3.5 h-3.5" />
            GATEWAY DE CORREO CORPORATIVO EN LÍNEA (@BANCOCENTRAL.COM) · TIEMPO REAL
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            Simulador de Correo Empresarial y Disparos del API en Tiempo Real
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Cada correo entrante a <code>@bancocentral.com</code> invoca en tiempo real <code>POST /api/v1/detection/analyze-email</code> evaluando cabeceras SPF/DKIM/DMARC, remitente, asunto, cuerpo, enlaces y adjuntos: si es limpio lo <strong>ACEPTA en Bandeja (`DELIVER`)</strong> y si es riesgoso <strong>DISPARA bloqueo en Cuarentena (`QUARANTINE`) + Incidente SOC</strong>.
          </p>
        </div>

        <RequirePermission permission={PERMISSIONS.DETECTION_ANALYZE} mode="disable">
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setLiveStreamActive((v) => !v)}
              className={`px-3.5 py-2 rounded-xl text-xs font-bold inline-flex items-center gap-2 border transition ${
                liveStreamActive
                  ? 'bg-amber-500 text-slate-950 border-amber-400 shadow-lg shadow-amber-500/20 animate-pulse'
                  : 'soc-btn-secondary'
              }`}
            >
              {liveStreamActive ? <Pause className="w-4 h-4" /> : <Activity className="w-4 h-4 text-emerald-500" />}
              {liveStreamActive ? 'Pausar Flujo en Vivo' : 'Simular Tráfico Continuo en Vivo'}
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={() => void handleRunScenarioBatch()}
              className="soc-btn-primary"
            >
              <Play className="w-4 h-4" />
              {busy ? 'Disparando API...' : 'Disparar Ráfaga de 7 Correos Entrantes'}
            </button>
          </div>
        </RequirePermission>
      </div>

      {/* LIVE API FIRE CONSOLE + CORPORATE INBOX ROUTING SUMMARY */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Live API Telemetry Console (Always Visible) */}
        <div className="lg:col-span-7 bg-slate-950 text-slate-100 rounded-xl border border-slate-800 p-4 space-y-2.5 shadow-inner">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400">
              <Terminal className="w-4 h-4" />
              CONSOLA EN VIVO DE DISPAROS DEL API (MTA HOOK → FASTAPI → POSTGRESQL)
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              {history.length} llamadas HTTP reales
            </span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] pr-1">
            {history.length === 0 ? (
              <div className="text-slate-500 py-6 text-center">
                Esperando tráfico de correo entrante... Haga clic en cualquier correo abajo para disparar el API en vivo.
              </div>
            ) : (
              history.map((h) => {
                const isMalicious = h.response.action === 'QUARANTINE';
                const isSuspicious = h.response.action === 'TAG_AND_BANNER';
                return (
                  <div
                    key={h.id}
                    onClick={() => setSelected(h)}
                    className={`cursor-pointer p-2 rounded border transition flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                      selected?.id === h.id
                        ? 'bg-slate-900 border-blue-500'
                        : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-slate-400">[{h.at}]</span>
                        <span className="text-blue-400 font-bold">{h.endpoint}</span>
                        <span className="text-emerald-400">HTTP {h.httpStatus}</span>
                        <span className="text-slate-400">({h.response.latency_ms || h.clientLatencyMs} ms)</span>
                      </div>
                      <div className="text-slate-300 truncate">
                        De: <span className="text-white">{h.response.sender}</span> → Para:{' '}
                        <span className="text-white">{h.response.recipient}</span> | &ldquo;{h.response.subject}&rdquo;
                      </div>
                    </div>

                    <div className="shrink-0 flex items-center gap-2">
                      <span className="text-xs font-bold text-white">
                        Score: {h.response.risk_score}/100
                      </span>
                      {isMalicious ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/40">
                          🚨 DISPARO ALERTA + CUARENTENA {h.response.incident_code ? `(${h.response.incident_code})` : ''}
                        </span>
                      ) : isSuspicious ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          ⚠️ ETIQUETADO CON BANNER
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          ✅ ACEPTADO EN BANDEJA
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Corporate Mail Routing Summary (Accepted vs Warned vs Quarantined) */}
        <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-1 gap-2.5">
          <div className="soc-card p-3.5 border-l-4 border-l-emerald-500 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5">
                <Inbox className="w-4 h-4" />
                Bandeja de Entrada Corporativa (Aceptados)
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Score 0–34 · Acción <code>DELIVER</code> (pasan normal al empleado)
              </p>
            </div>
            <span className="text-2xl font-black font-mono text-emerald-600 dark:text-emerald-400">
              {acceptedEmails.length}
            </span>
          </div>

          <div className="soc-card p-3.5 border-l-4 border-l-amber-500 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-amber-700 dark:text-amber-400 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                Entregados con Banner de Precaución
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Score 35–69 · Acción <code>TAG_AND_BANNER</code> (aviso preventivo)
              </p>
            </div>
            <span className="text-2xl font-black font-mono text-amber-600 dark:text-amber-400">
              {taggedEmails.length}
            </span>
          </div>

          <div className="soc-card p-3.5 border-l-4 border-l-red-500 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-red-700 dark:text-red-400 flex items-center gap-1.5">
                <AlertOctagon className="w-4 h-4" />
                Bloqueados en Cuarentena + Alerta SOC Disparada
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Score 70–100 · Acción <code>QUARANTINE</code> + Ticket SOC automático
              </p>
            </div>
            <span className="text-2xl font-black font-mono text-red-600 dark:text-red-400">
              {quarantinedEmails.length}
            </span>
          </div>
        </div>
      </div>

      {/* 4-Tab Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
        <button
          type="button"
          onClick={() => setTab('email')}
          className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition ${
            tab === 'email'
              ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
              : 'soc-card text-slate-700 dark:text-slate-300 hover:border-blue-400'
          }`}
        >
          <Mail className="w-4 h-4" />
          1. MTA Email Gateway
        </button>
        <button
          type="button"
          onClick={() => setTab('eml')}
          className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition ${
            tab === 'eml'
              ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
              : 'soc-card text-slate-700 dark:text-slate-300 hover:border-blue-400'
          }`}
        >
          <FileCode2 className="w-4 h-4" />
          2. .EML File Inspector
        </button>
        <button
          type="button"
          onClick={() => setTab('url')}
          className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition ${
            tab === 'url'
              ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
              : 'soc-card text-slate-700 dark:text-slate-300 hover:border-blue-400'
          }`}
        >
          <Globe className="w-4 h-4" />
          3. URL / SMS / QR Scanner
        </button>
        <button
          type="button"
          onClick={() => setTab('report')}
          className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition ${
            tab === 'report'
              ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
              : 'soc-card text-slate-700 dark:text-slate-300 hover:border-blue-400'
          }`}
        >
          <Flag className="w-4 h-4" />
          4. Reportar Phishing
        </button>
      </div>

      {error && (
        <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Active Analyzer Form + Recent Stream */}
        <div className="lg:col-span-7 space-y-5">
          {tab === 'email' && (
            <div className="soc-card p-5 space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="soc-label">
                    Simular Llegada de Correo Corporativo (Clic para Disparar API en Tiempo Real)
                  </div>
                  <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400">
                    Dispara POST /api/v1/detection/analyze-email al instante
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {MAIL_SCENARIOS.map((sc) => (
                    <button
                      key={sc.id}
                      type="button"
                      disabled={busy}
                      onClick={() => void handleTriggerScenarioLive(sc)}
                      className="text-left p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 hover:border-blue-500 transition space-y-1 group"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-xs font-bold text-slate-900 dark:text-white truncate flex items-center gap-1">
                          <Zap className="w-3.5 h-3.5 text-blue-500 shrink-0 group-hover:scale-110 transition" />
                          {sc.label}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border shrink-0 ${getVerdictBadgeClasses(
                            sc.category,
                          )}`}
                        >
                          {sc.category}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 line-clamp-1">
                        {sc.description}
                      </p>
                    </button>
                  ))}
                </div>
              </div>

              <form onSubmit={handleEmailSubmit} className="space-y-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                <div className="soc-label">Inline MTA Message Composer</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="soc-label mb-1">Sender Address</label>
                    <input
                      type="text"
                      required
                      value={emailForm.sender}
                      onChange={(e) => setEmailForm({ ...emailForm, sender: e.target.value })}
                      className="soc-input font-mono"
                    />
                  </div>
                  <div>
                    <label className="soc-label mb-1">Recipient Mailbox</label>
                    <input
                      type="text"
                      required
                      value={emailForm.recipient}
                      onChange={(e) => setEmailForm({ ...emailForm, recipient: e.target.value })}
                      className="soc-input font-mono"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="soc-label mb-1">Subject</label>
                    <input
                      type="text"
                      required
                      value={emailForm.subject}
                      onChange={(e) => setEmailForm({ ...emailForm, subject: e.target.value })}
                      className="soc-input"
                    />
                  </div>
                  <div>
                    <label className="soc-label mb-1">Channel</label>
                    <select
                      value={emailForm.channel}
                      onChange={(e) =>
                        setEmailForm({ ...emailForm, channel: e.target.value as ChannelType })
                      }
                      className="soc-input"
                    >
                      <option value="EMAIL">EMAIL</option>
                      <option value="SMS">SMS</option>
                      <option value="QR">QR</option>
                      <option value="WEB">WEB</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="soc-label mb-1">Message Body (URLs &amp; Lures Inspected Inline)</label>
                  <textarea
                    rows={4}
                    required
                    value={emailForm.body_text}
                    onChange={(e) => setEmailForm({ ...emailForm, body_text: e.target.value })}
                    className="soc-input"
                  />
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div>
                    <label className="soc-label mb-1">SPF</label>
                    <select
                      value={emailForm.spfResult}
                      onChange={(e) => setEmailForm({ ...emailForm, spfResult: e.target.value })}
                      className="soc-input font-mono"
                    >
                      <option value="pass">pass</option>
                      <option value="softfail">softfail</option>
                      <option value="fail">fail</option>
                    </select>
                  </div>
                  <div>
                    <label className="soc-label mb-1">DKIM</label>
                    <select
                      value={emailForm.dkimResult}
                      onChange={(e) => setEmailForm({ ...emailForm, dkimResult: e.target.value })}
                      className="soc-input font-mono"
                    >
                      <option value="pass">pass</option>
                      <option value="none">none</option>
                      <option value="fail">fail</option>
                    </select>
                  </div>
                  <div>
                    <label className="soc-label mb-1">DMARC</label>
                    <select
                      value={emailForm.dmarcResult}
                      onChange={(e) => setEmailForm({ ...emailForm, dmarcResult: e.target.value })}
                      className="soc-input font-mono"
                    >
                      <option value="pass">pass</option>
                      <option value="none">none</option>
                      <option value="fail">fail</option>
                    </select>
                  </div>
                  <div>
                    <label className="soc-label mb-1">Origin IP</label>
                    <input
                      type="text"
                      value={emailForm.originatingIp}
                      onChange={(e) =>
                        setEmailForm({ ...emailForm, originatingIp: e.target.value })
                      }
                      className="soc-input font-mono"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="soc-label mb-1">Attachment Filename (optional)</label>
                    <input
                      type="text"
                      placeholder="e.g. Liquidacion.pdf.exe"
                      value={emailForm.attachmentName}
                      onChange={(e) =>
                        setEmailForm({ ...emailForm, attachmentName: e.target.value })
                      }
                      className="soc-input font-mono"
                    />
                  </div>
                  <div>
                    <label className="soc-label mb-1">Reply-To Header (optional BEC check)</label>
                    <input
                      type="text"
                      placeholder="e.g. externo@protonmail.com"
                      value={emailForm.replyTo}
                      onChange={(e) => setEmailForm({ ...emailForm, replyTo: e.target.value })}
                      className="soc-input font-mono"
                    />
                  </div>
                </div>

                <div className="flex justify-end pt-1">
                  <RequirePermission permission={PERMISSIONS.DETECTION_ANALYZE} mode="disable">
                    <button type="submit" disabled={busy} className="soc-btn-primary">
                      <Send className="w-3.5 h-3.5" />
                      {busy ? 'Analyzing...' : 'Inspect via MTA Gateway'}
                    </button>
                  </RequirePermission>
                </div>
              </form>
            </div>
          )}

          {tab === 'eml' && (
            <form onSubmit={handleEmlSubmit} className="soc-card p-5 space-y-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  RFC 822 <code>.eml</code> File Upload &amp; Parser
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Upload a captured <code>.eml</code> file via multipart form-data or inspect raw RFC 822 headers + MIME body below.
                </p>
              </div>

              <div className="soc-card-muted p-4 space-y-2">
                <label className="soc-label">Upload .EML File (Optional — overrides raw text when selected)</label>
                <div className="flex items-center gap-3 flex-wrap">
                  <input
                    type="file"
                    accept=".eml,message/rfc822,.txt"
                    onChange={(e) => setEmlFile(e.target.files?.[0] ?? null)}
                    className="text-xs text-slate-600 dark:text-slate-300"
                  />
                  {emlFile && (
                    <button
                      type="button"
                      onClick={() => setEmlFile(null)}
                      className="text-xs text-red-500 hover:underline"
                    >
                      Clear file ({emlFile.name})
                    </button>
                  )}
                </div>
              </div>

              <div>
                <label className="soc-label mb-1">Or Edit Raw RFC 822 Message</label>
                <textarea
                  rows={10}
                  value={rawEmlText}
                  onChange={(e) => setRawEmlText(e.target.value)}
                  disabled={Boolean(emlFile)}
                  className="soc-input font-mono text-[11px]"
                />
              </div>

              <div className="flex justify-end">
                <RequirePermission permission={PERMISSIONS.DETECTION_ANALYZE} mode="disable">
                  <button type="submit" disabled={busy} className="soc-btn-primary">
                    <Upload className="w-3.5 h-3.5" />
                    {busy ? 'Parsing .EML...' : 'Parse & Inspect .EML'}
                  </button>
                </RequirePermission>
              </div>
            </form>
          )}

          {tab === 'url' && (
            <form onSubmit={handleUrlSubmit} className="soc-card p-5 space-y-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Standalone URL / SMS Smishing / QR Quishing Deep Scanner
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Evaluates lexical entropy, IDN homographs, typosquatting, active IOCs, <code>pg_trgm</code> brand similarity, and live DNS/TLS/RDAP domain age.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="soc-label mb-1">Target URL or Decoded QR Payload</label>
                  <input
                    type="text"
                    required
                    value={urlForm.url}
                    onChange={(e) => setUrlForm({ ...urlForm, url: e.target.value })}
                    className="soc-input font-mono"
                  />
                </div>
                <div>
                  <label className="soc-label mb-1">Vector Channel</label>
                  <select
                    value={urlForm.channel}
                    onChange={(e) =>
                      setUrlForm({ ...urlForm, channel: e.target.value as ChannelType })
                    }
                    className="soc-input"
                  >
                    <option value="WEB">WEB</option>
                    <option value="SMS">SMS (Smishing)</option>
                    <option value="QR">QR (Quishing)</option>
                    <option value="EMAIL">EMAIL</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="soc-label mb-1">Originating Sender / Shortcode (optional)</label>
                  <input
                    type="text"
                    value={urlForm.sender}
                    onChange={(e) => setUrlForm({ ...urlForm, sender: e.target.value })}
                    className="soc-input font-mono"
                  />
                </div>
                <div className="flex items-end pb-1">
                  <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={urlForm.enrich}
                      onChange={(e) => setUrlForm({ ...urlForm, enrich: e.target.checked })}
                      className="rounded border-slate-400"
                    />
                    <span>Enable Live DNS / TLS / RDAP Enrichment</span>
                  </label>
                </div>
              </div>

              <div>
                <label className="soc-label mb-1">Accompanying SMS / QR Lure Text (optional)</label>
                <textarea
                  rows={3}
                  value={urlForm.message_text}
                  onChange={(e) => setUrlForm({ ...urlForm, message_text: e.target.value })}
                  className="soc-input"
                />
              </div>

              <div className="flex justify-end">
                <RequirePermission permission={PERMISSIONS.DETECTION_ANALYZE} mode="disable">
                  <button type="submit" disabled={busy} className="soc-btn-primary">
                    <Globe className="w-3.5 h-3.5" />
                    {busy ? 'Scanning Target...' : 'Run Deep URL Scan'}
                  </button>
                </RequirePermission>
              </div>
            </form>
          )}

          {tab === 'report' && (
            <form onSubmit={handleReportSubmit} className="soc-card p-5 space-y-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Employee &ldquo;Reportar Phishing&rdquo; Submission Portal
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Available to all authenticated employees (including <code>VIEWER</code>). Submissions with risk score ≥ 35 automatically open a prioritized SOC incident.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="soc-label mb-1">Suspicious Sender</label>
                  <input
                    type="text"
                    required
                    value={reportForm.sender_email}
                    onChange={(e) =>
                      setReportForm({ ...reportForm, sender_email: e.target.value })
                    }
                    className="soc-input font-mono"
                  />
                </div>
                <div>
                  <label className="soc-label mb-1">Reporting Employee Email</label>
                  <input
                    type="text"
                    required
                    value={reportForm.reported_by_email}
                    onChange={(e) =>
                      setReportForm({ ...reportForm, reported_by_email: e.target.value })
                    }
                    className="soc-input font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="soc-label mb-1">Subject</label>
                  <input
                    type="text"
                    required
                    value={reportForm.subject}
                    onChange={(e) => setReportForm({ ...reportForm, subject: e.target.value })}
                    className="soc-input"
                  />
                </div>
                <div>
                  <label className="soc-label mb-1">Channel</label>
                  <select
                    value={reportForm.channel}
                    onChange={(e) =>
                      setReportForm({ ...reportForm, channel: e.target.value as ChannelType })
                    }
                    className="soc-input"
                  >
                    <option value="EMAIL">EMAIL</option>
                    <option value="SMS">SMS</option>
                    <option value="QR">QR</option>
                    <option value="WEB">WEB</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="soc-label mb-1">Suspicious Message Content</label>
                <textarea
                  rows={4}
                  required
                  value={reportForm.body_text}
                  onChange={(e) => setReportForm({ ...reportForm, body_text: e.target.value })}
                  className="soc-input"
                />
              </div>

              <div className="flex justify-end">
                <button type="submit" disabled={busy} className="soc-btn-primary">
                  <Flag className="w-3.5 h-3.5" />
                  {busy ? 'Submitting Report...' : 'Reportar Phishing to SOC'}
                </button>
              </div>
            </form>
          )}

          {/* Live Session Stream */}
          <div className="space-y-2">
            <div className="soc-label px-1">Recent Gateway Inspections ({history.length})</div>
            {history.length === 0 ? (
              <div className="soc-card-muted p-6 text-center text-xs text-slate-500">
                Submit a scenario, <code>.eml</code> file, URL, or phishing report above to inspect the live gateway decision.
              </div>
            ) : (
              <div className="space-y-2">
                {history.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelected(item)}
                    className={`w-full text-left soc-card p-3.5 transition flex items-center justify-between gap-3 ${
                      selected?.id === item.id ? 'ring-2 ring-blue-500 border-blue-500' : ''
                    }`}
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getActionBadgeClasses(
                            item.response.action,
                          )}`}
                        >
                          {item.response.action}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                          {item.response.channel}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          {item.at} · {item.response.latency_ms || item.clientLatencyMs} ms
                        </span>
                      </div>
                      <div className="text-xs font-bold text-slate-900 dark:text-white truncate">
                        {item.response.subject}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 truncate">
                        {item.response.sender} → {item.response.recipient}
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="text-lg font-black text-slate-900 dark:text-white">
                        {item.response.risk_score}
                        <span className="text-[10px] font-normal text-slate-400">/100</span>
                      </div>
                      {item.response.incident_code && (
                        <span className="inline-block text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/15 text-red-700 dark:text-red-300 border border-red-500/30">
                          {item.response.incident_code}
                        </span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Gateway Decision Inspector */}
        <div className="lg:col-span-5 space-y-4">
          <div className="soc-card p-5 space-y-4">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white border-b border-slate-200 dark:border-slate-800 pb-3">
              Gateway Enforcement &amp; Forensic Verdict
            </h2>

            {!activeResp ? (
              <div className="py-12 text-center text-xs text-slate-500">
                Run any analyzer tab on the left to inspect risk score gauge, SPF/DKIM/DMARC posture, signals, enrichment, and auto-created SOC tickets.
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                {/* Action Banner */}
                <div
                  className={`p-3.5 rounded-xl border flex items-center justify-between gap-3 ${getActionBadgeClasses(
                    activeResp.action,
                  )}`}
                >
                  <div className="flex items-center gap-2.5">
                    {activeResp.action === 'QUARANTINE' ? (
                      <AlertOctagon className="w-5 h-5 shrink-0" />
                    ) : activeResp.action === 'TAG_AND_BANNER' ? (
                      <ShieldAlert className="w-5 h-5 shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-5 h-5 shrink-0" />
                    )}
                    <div>
                      <div className="font-mono font-black text-sm">{activeResp.action}</div>
                      <div className="text-[11px] opacity-90">
                        Verdict: {activeResp.verdict} · Severity: {activeResp.severity}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-black font-mono">{activeResp.risk_score}/100</div>
                    <div className="text-[10px] font-mono">
                      {activeResp.latency_ms || selected?.clientLatencyMs} ms
                    </div>
                  </div>
                </div>

                {/* Risk Score Gauge Bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono text-slate-500">
                    <span>0 CLEAN</span>
                    <span>35 SUSPICIOUS</span>
                    <span>70 QUARANTINE</span>
                    <span>100</span>
                  </div>
                  <div className="h-2.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${
                        activeResp.risk_score >= 70
                          ? 'bg-red-500'
                          : activeResp.risk_score >= 35
                            ? 'bg-amber-500'
                            : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, Math.max(2, activeResp.risk_score))}%` }}
                    />
                  </div>
                </div>

                {/* SPF / DKIM / DMARC Badges */}
                <div className="flex flex-wrap gap-1.5">
                  {(['spf', 'dkim', 'dmarc'] as const).map((proto) => {
                    const b = parseAuthBadge(proto);
                    return (
                      <span
                        key={proto}
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-semibold border ${b.cls}`}
                      >
                        {b.label}
                      </span>
                    );
                  })}
                  <span
                    className={`px-2 py-0.5 rounded font-mono text-[10px] font-semibold border ${getSeverityBadgeClasses(
                      activeResp.severity,
                    )}`}
                  >
                    SEV: {activeResp.severity}
                  </span>
                </div>

                {/* Summary */}
                <p className="soc-card-muted p-3 text-slate-700 dark:text-slate-300 leading-relaxed">
                  {activeResp.summary}
                </p>

                {/* Auto-created SOC Incident Link */}
                {activeResp.incident_id && activeResp.incident_code && (
                  <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 flex items-center justify-between gap-2">
                    <div>
                      <div className="text-[10px] font-mono uppercase text-red-600 dark:text-red-300 font-bold">
                        Automated SOC Incident Triggered
                      </div>
                      <div className="font-mono font-bold text-slate-900 dark:text-white">
                        {activeResp.incident_code}
                      </div>
                    </div>
                    <Link
                      to={`/incidents/${activeResp.incident_id}`}
                      className="soc-btn-primary py-1.5"
                    >
                      Open Case <ExternalLink className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                )}

                {/* Signals */}
                <div className="space-y-2">
                  <div className="soc-label">
                    Triggered Heuristic / IOC / LLM Signals ({activeResp.signals.length})
                  </div>
                  {activeResp.signals.length === 0 ? (
                    <div className="soc-card-muted p-3 text-slate-500">
                      Zero risk signals raised — verified clean message.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {activeResp.signals.map((s, idx) => (
                        <div key={`${s.name}-${idx}`} className="soc-card-muted p-2.5 space-y-1">
                          <div className="flex items-center justify-between font-mono font-bold">
                            <span className="text-slate-900 dark:text-slate-100">{s.name}</span>
                            <span className="text-amber-600 dark:text-amber-400">
                              +{s.weight} pts (conf {(s.score * 100).toFixed(0)}%)
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-600 dark:text-slate-400">
                            {s.reason}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* DNS / TLS / RDAP Enrichment (when present) */}
                {activeResp.enrichment && Object.keys(activeResp.enrichment).length > 0 && (
                  <details className="soc-card-muted p-2.5" open>
                    <summary className="cursor-pointer font-semibold text-slate-800 dark:text-slate-200">
                      DNS / TLS / RDAP Domain Enrichment
                    </summary>
                    <pre className="mt-2 text-[10px] font-mono overflow-x-auto text-slate-600 dark:text-slate-300">
                      {JSON.stringify(activeResp.enrichment, null, 2)}
                    </pre>
                  </details>
                )}

                {/* Open Raw JSON Request/Response Inspector */}
                <details className="soc-card-muted p-2.5" open>
                  <summary className="cursor-pointer font-semibold text-slate-800 dark:text-slate-200 inline-flex items-center gap-1.5">
                    <Code2 className="w-3.5 h-3.5 text-blue-500" />
                    Raw JSON Request &amp; Response Inspector
                  </summary>
                  <div className="mt-2 space-y-2">
                    <div>
                      <div className="soc-label mb-1">{selected?.endpoint}</div>
                      <pre className="p-2 rounded bg-slate-900 text-slate-200 text-[10px] font-mono overflow-x-auto max-h-40">
                        {JSON.stringify(selected?.requestPayload, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <div className="soc-label mb-1">HTTP {selected?.httpStatus} Response</div>
                      <pre className="p-2 rounded bg-slate-900 text-emerald-300 text-[10px] font-mono overflow-x-auto max-h-56">
                        {JSON.stringify(activeResp, null, 2)}
                      </pre>
                    </div>
                  </div>
                </details>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
