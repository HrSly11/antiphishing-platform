import { useEffect, useState } from 'react';
import {
  Bot,
  BookOpen,
  Download,
  Globe,
  MessageSquare,
  Network,
  Send,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import {
  getActionBadgeClasses,
  getVerdictBadgeClasses,
  triggerBlobDownload,
} from '../lib/formatters';
import type {
  AssistantChatResponse,
  LangFlowListResponse,
  LangFlowSandboxItem,
  UrlInvestigationResponse,
} from '../types/domain';

type CopilotTab = 'rag' | 'url' | 'langflow';

interface ChatTurn {
  id: string;
  question: string;
  response: AssistantChatResponse;
  at: string;
}

const QUICK_PROMPTS = [
  'What is the SOC SLA deadline and containment playbook for CRITICAL homograph incidents?',
  'Summarize PCI-DSS v4.0 Req 5.4.1 and Req 10.2 controls enforced by the platform.',
  'How do we handle a BEC wire fraud attempt targeting Treasury?',
  'Give me the live 30-day detection telemetry and open incident posture.',
];

export function SocChatWidget() {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<CopilotTab>('rag');

  // Tab 1: RAG Assistant
  const [question, setQuestion] = useState('');
  const [incidentContextId, setIncidentContextId] = useState('');
  const [chatHistory, setChatHistory] = useState<ChatTurn[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);

  // Tab 2: LangChain URL Agent
  const [targetUrl, setTargetUrl] = useState('http://bancocentral-seguridad.com/login-token');
  const [enableNetTools, setEnableNetTools] = useState(true);
  const [urlResult, setUrlResult] = useState<UrlInvestigationResponse | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);

  // Tab 3: LangFlow Sandboxes
  const [flows, setFlows] = useState<LangFlowSandboxItem[]>([]);
  const [flowsLoading, setFlowsLoading] = useState(false);
  const [selectedFlowIdx, setSelectedFlowIdx] = useState(0);

  useEffect(() => {
    if (open && tab === 'langflow' && flows.length === 0) {
      setFlowsLoading(true);
      apiClient
        .get<LangFlowListResponse>('/assistant/flows')
        .then((res) => setFlows(res.data.flows ?? []))
        .catch(() => setFlows([]))
        .finally(() => setFlowsLoading(false));
    }
  }, [open, tab, flows.length]);

  const askAssistant = async (promptText: string) => {
    const q = promptText.trim();
    if (q.length < 2) return;
    setChatLoading(true);
    setChatError(null);
    try {
      const res = await apiClient.post<AssistantChatResponse>('/assistant/chat', {
        question: q,
        incident_id: incidentContextId.trim() || undefined,
        top_k: 4,
      });
      setChatHistory((prev) => [
        {
          id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
          question: q,
          response: res.data,
          at: new Date().toLocaleTimeString(),
        },
        ...prev,
      ]);
      setQuestion('');
    } catch (err) {
      setChatError(extractApiError(err));
    } finally {
      setChatLoading(false);
    }
  };

  const handleUrlInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    setUrlLoading(true);
    setUrlError(null);
    try {
      const res = await apiClient.post<UrlInvestigationResponse>('/assistant/investigate-url', {
        url: targetUrl.trim(),
        enable_network_tools: enableNetTools,
      });
      setUrlResult(res.data);
    } catch (err) {
      setUrlError(extractApiError(err));
    } finally {
      setUrlLoading(false);
    }
  };

  const exportLangFlowJson = (item: LangFlowSandboxItem) => {
    const jsonBytes = new Blob([JSON.stringify(item.flow, null, 2)], {
      type: 'application/json',
    });
    triggerBlobDownload(jsonBytes, item.filename || `${item.name}.json`);
  };

  const activeFlow = flows[selectedFlowIdx] ?? null;
  const activeFlowData = (activeFlow?.flow?.data as
    | { nodes?: Array<Record<string, unknown>>; edges?: Array<Record<string, unknown>> }
    | undefined) ?? {
    nodes: (activeFlow?.flow?.nodes as Array<Record<string, unknown>> | undefined) ?? [],
    edges: (activeFlow?.flow?.edges as Array<Record<string, unknown>> | undefined) ?? [],
  };
  const flowNodes = activeFlowData.nodes ?? [];
  const flowEdges = activeFlowData.edges ?? [];

  return (
    <>
      {/* Persistent Floating Trigger */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="fixed bottom-5 right-5 z-40 inline-flex items-center gap-2 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 px-4 py-3 text-xs font-bold text-white shadow-xl shadow-blue-900/30 transition hover:scale-[1.02] hover:from-blue-500 hover:to-indigo-500"
        title="Open On-Premise SOC AI Copilot & LangFlow Sandbox"
      >
        <Sparkles className="w-4 h-4" />
        <span>SOC AI Copilot</span>
      </button>

      {open && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-white dark:bg-slate-950 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col">
          {/* Header */}
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/90 dark:bg-slate-900/90">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center shadow-sm">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  SentinelBank SOC AI Copilot
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  100% On-Premise LangChain RAG · Multi-Tool URL Agent · LangFlow v1
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-200/70 dark:hover:bg-slate-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* 3-Tab Switcher */}
          <div className="grid grid-cols-3 border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-slate-900/50 p-1.5 gap-1.5 text-xs">
            <button
              type="button"
              onClick={() => setTab('rag')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-semibold transition ${
                tab === 'rag'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              SOC RAG Chat
            </button>
            <button
              type="button"
              onClick={() => setTab('url')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-semibold transition ${
                tab === 'url'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              URL Agent
            </button>
            <button
              type="button"
              onClick={() => setTab('langflow')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-semibold transition ${
                tab === 'langflow'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              LangFlow
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
            {tab === 'rag' && (
              <>
                <div className="space-y-2">
                  <div className="soc-label">Quick Grounded Runbook Prompts</div>
                  <div className="flex flex-wrap gap-1.5">
                    {QUICK_PROMPTS.map((p) => (
                      <button
                        key={p}
                        type="button"
                        disabled={chatLoading}
                        onClick={() => askAssistant(p)}
                        className="text-left px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 hover:border-blue-500 text-[11px] text-slate-700 dark:text-slate-300 transition"
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void askAssistant(question);
                  }}
                  className="soc-card p-3 space-y-2.5"
                >
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <div className="sm:col-span-2">
                      <input
                        type="text"
                        placeholder="Ask about playbooks, SLA, PCI-DSS, ISO 27001, or live KPIs..."
                        value={question}
                        onChange={(e) => setQuestion(e.target.value)}
                        className="soc-input"
                        required
                      />
                    </div>
                    <div>
                      <input
                        type="text"
                        placeholder="Incident Code (optional)"
                        value={incidentContextId}
                        onChange={(e) => setIncidentContextId(e.target.value)}
                        className="soc-input font-mono"
                      />
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] text-slate-500">
                      Grounded on <code>docs/runbooks</code> &amp; live PostgreSQL telemetry
                    </span>
                    <button type="submit" disabled={chatLoading} className="soc-btn-primary py-1.5">
                      <Send className="w-3.5 h-3.5" />
                      {chatLoading ? 'Querying...' : 'Ask Copilot'}
                    </button>
                  </div>
                </form>

                {chatError && (
                  <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300">
                    {chatError}
                  </div>
                )}

                <div className="space-y-3">
                  {chatHistory.length === 0 ? (
                    <div className="soc-card-muted p-6 text-center text-slate-500">
                      Select a runbook prompt above or ask any operational question to retrieve cited SOC guidance.
                    </div>
                  ) : (
                    chatHistory.map((turn) => (
                      <div key={turn.id} className="soc-card p-3.5 space-y-2.5">
                        <div className="flex items-start justify-between gap-2">
                          <div className="font-semibold text-slate-900 dark:text-white">
                            Q: {turn.question}
                          </div>
                          <span className="text-[10px] font-mono text-slate-400 shrink-0">
                            {turn.at}
                          </span>
                        </div>

                        {turn.response.injection_detected && (
                          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-600 dark:text-red-300 text-[10px] font-semibold">
                            <ShieldAlert className="w-3 h-3" />
                            Prompt-Injection Guard Triggered
                          </div>
                        )}

                        <div className="whitespace-pre-line text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-950/60 p-3 rounded-lg border border-slate-200/80 dark:border-slate-800">
                          {turn.response.answer}
                        </div>

                        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <BookOpen className="w-3.5 h-3.5 text-blue-500" />
                            {turn.response.citations.length > 0 ? (
                              turn.response.citations.map((cit) => (
                                <span
                                  key={cit}
                                  className="px-2 py-0.5 rounded font-mono text-[10px] bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-500/25"
                                >
                                  {cit}
                                </span>
                              ))
                            ) : (
                              <span className="text-[10px] text-slate-400">Live DB telemetry</span>
                            )}
                          </div>
                          <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                            {turn.response.engine}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </>
            )}

            {tab === 'url' && (
              <div className="space-y-4">
                <form onSubmit={handleUrlInvestigation} className="soc-card p-3.5 space-y-3">
                  <div>
                    <label className="soc-label mb-1">Suspicious URL Target</label>
                    <input
                      type="text"
                      required
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://xn--banccentral-9ib.com/sso/login"
                      className="soc-input font-mono"
                    />
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <label className="inline-flex items-center gap-2 text-slate-600 dark:text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={enableNetTools}
                        onChange={(e) => setEnableNetTools(e.target.checked)}
                        className="rounded border-slate-400"
                      />
                      <span>Enable WHOIS/RDAP, DNS &amp; TLS tools</span>
                    </label>
                    <button type="submit" disabled={urlLoading} className="soc-btn-primary">
                      {urlLoading ? 'Investigating...' : 'Run Multi-Tool Agent'}
                    </button>
                  </div>
                </form>

                {urlError && (
                  <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300">
                    {urlError}
                  </div>
                )}

                {urlResult && (
                  <div className="soc-card p-4 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${getVerdictBadgeClasses(
                            urlResult.verdict,
                          )}`}
                        >
                          {urlResult.verdict} · {urlResult.risk_score}/100
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getActionBadgeClasses(
                            urlResult.action,
                          )}`}
                        >
                          {urlResult.action}
                        </span>
                      </div>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {urlResult.engine}
                      </span>
                    </div>

                    <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 break-all">
                      Domain: <strong className="text-slate-900 dark:text-white">{urlResult.domain}</strong>
                    </div>

                    <p className="soc-card-muted p-2.5 text-slate-700 dark:text-slate-300">
                      {urlResult.summary}
                    </p>

                    <div className="space-y-1.5">
                      <div className="soc-label">Triggered Agent Signals ({urlResult.signals.length})</div>
                      {urlResult.signals.length === 0 ? (
                        <div className="text-slate-500">No risk signals triggered.</div>
                      ) : (
                        urlResult.signals.map((sig, i) => (
                          <div key={`${sig.name}-${i}`} className="soc-card-muted p-2">
                            <div className="flex justify-between font-semibold">
                              <span className="font-mono text-slate-900 dark:text-slate-100">{sig.name}</span>
                              <span className="text-amber-600 dark:text-amber-400">+{sig.weight} pts</span>
                            </div>
                            <div className="text-[11px] text-slate-600 dark:text-slate-400">{sig.reason}</div>
                          </div>
                        ))
                      )}
                    </div>

                    <details className="soc-card-muted p-2.5">
                      <summary className="cursor-pointer font-semibold text-slate-700 dark:text-slate-300">
                        Inspect Multi-Tool Observations (blacklist, pg_trgm, DNS/TLS/RDAP)
                      </summary>
                      <pre className="mt-2 text-[10px] font-mono overflow-x-auto text-slate-600 dark:text-slate-300">
                        {JSON.stringify(urlResult.tool_observations, null, 2)}
                      </pre>
                    </details>
                  </div>
                )}
              </div>
            )}

            {tab === 'langflow' && (
              <div className="space-y-4">
                {flowsLoading ? (
                  <div className="soc-card-muted p-6 text-center text-slate-500">
                    Loading LangFlow visual sandboxes...
                  </div>
                ) : flows.length === 0 ? (
                  <div className="soc-card-muted p-6 text-center text-slate-500">
                    No LangFlow sandbox definitions found.
                  </div>
                ) : (
                  <>
                    <div className="flex flex-wrap gap-2">
                      {flows.map((f, idx) => (
                        <button
                          key={f.filename}
                          type="button"
                          onClick={() => setSelectedFlowIdx(idx)}
                          className={`px-3 py-1.5 rounded-lg font-mono text-xs border transition ${
                            selectedFlowIdx === idx
                              ? 'bg-blue-600 text-white border-blue-500'
                              : 'soc-card text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          {f.name}
                        </button>
                      ))}
                    </div>

                    {activeFlow && (
                      <div className="soc-card p-4 space-y-3">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                              {activeFlow.name}
                            </h3>
                            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                              {activeFlow.description ??
                                String(activeFlow.flow?.description ?? 'Exportable LangFlow v1 pipeline')}
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={() => exportLangFlowJson(activeFlow)}
                            className="soc-btn-secondary shrink-0"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Export JSON
                          </button>
                        </div>

                        <div className="grid grid-cols-2 gap-2">
                          <div className="soc-card-muted p-2.5">
                            <span className="soc-label">DAG Nodes</span>
                            <div className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
                              {activeFlow.node_count ?? flowNodes.length}
                            </div>
                          </div>
                          <div className="soc-card-muted p-2.5">
                            <span className="soc-label">Pipeline Edges</span>
                            <div className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
                              {activeFlow.edge_count ?? flowEdges.length}
                            </div>
                          </div>
                        </div>

                        {flowNodes.length > 0 && (
                          <div className="space-y-1.5">
                            <div className="soc-label">Visual Graph Nodes</div>
                            <div className="space-y-1.5">
                              {flowNodes.map((node, idx) => {
                                const nodeData = (node.data as Record<string, unknown> | undefined) ?? {};
                                const nodeId = String(node.id ?? `node-${idx}`);
                                const nodeType = String(
                                  nodeData.type ?? node.type ?? nodeData.display_name ?? 'RunnableNode',
                                );
                                const label = String(
                                  nodeData.display_name ?? nodeData.label ?? node.name ?? nodeId,
                                );
                                return (
                                  <div
                                    key={nodeId}
                                    className="soc-card-muted p-2.5 flex items-center justify-between gap-2"
                                  >
                                    <div>
                                      <div className="font-semibold text-slate-900 dark:text-slate-100">
                                        {idx + 1}. {label}
                                      </div>
                                      <div className="font-mono text-[10px] text-slate-500">
                                        id={nodeId}
                                      </div>
                                    </div>
                                    <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                                      {nodeType}
                                    </span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {flowEdges.length > 0 && (
                          <div className="space-y-1">
                            <div className="soc-label">Directed Edges</div>
                            <div className="flex flex-wrap gap-1.5">
                              {flowEdges.map((edge, idx) => (
                                <span
                                  key={idx}
                                  className="px-2 py-1 rounded font-mono text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700"
                                >
                                  {String(edge.source ?? '?')} → {String(edge.target ?? '?')}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        <details className="soc-card-muted p-2.5">
                          <summary className="cursor-pointer font-semibold text-slate-700 dark:text-slate-300">
                            Raw LangFlow Definition ({activeFlow.filename})
                          </summary>
                          <pre className="mt-2 text-[10px] font-mono max-h-60 overflow-auto text-slate-600 dark:text-slate-300">
                            {JSON.stringify(activeFlow.flow, null, 2)}
                          </pre>
                        </details>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export default SocChatWidget;
