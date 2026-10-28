export type RoleName = 'ADMIN' | 'SOC_L2' | 'SOC_L1' | 'AUDITOR' | 'VIEWER';

export type ChannelType = 'EMAIL' | 'SMS' | 'WEB' | 'QR';
export type VerdictType = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
export type GatewayActionType = 'DELIVER' | 'TAG_AND_BANNER' | 'QUARANTINE';
export type AnalystLabelType = 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNREVIEWED';
export type SeverityType = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatusType = 'OPEN' | 'TRIAGED' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
export type IncidentResolutionType =
  | 'TRUE_POSITIVE'
  | 'FALSE_POSITIVE'
  | 'BENIGN_POLICY_VIOLATION'
  | 'DUPLICATE';

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  role: RoleName;
  is_active: boolean;
  mfa_enabled: boolean;
  locked: boolean;
  failed_login_attempts: number;
  locked_until: string | null;
  last_login_at: string | null;
  created_at: string;
  permissions: string[];
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
  permissions: string[];
}

export interface SsoProviderItem {
  provider: string;
  protocol?: string;
  enabled: boolean;
  ready?: boolean;
  status?: string;
  details?: string;
  [key: string]: unknown;
}

export interface SsoProvidersResponse {
  primary_mode: string;
  providers: SsoProviderItem[];
}

export interface MfaSetupResponse {
  secret: string;
  otpauth_uri: string;
  issuer: string;
  mfa_enabled: boolean;
}

export interface RbacMatrixResponse {
  all_permissions: string[];
  roles: Array<{
    role: RoleName;
    permissions: string[];
  }>;
}

export interface EmailAttachmentDto {
  filename: string;
  size_bytes?: number;
  content_type?: string | null;
}

export interface EmailAnalysisRequest {
  sender: string;
  recipient: string;
  subject: string;
  body_text: string;
  body_html?: string | null;
  headers?: Record<string, string>;
  attachments?: EmailAttachmentDto[];
  channel?: ChannelType;
  reported_by_user?: boolean;
}

export interface UrlAnalysisRequest {
  url: string;
  channel?: ChannelType;
  sender?: string;
  recipient?: string;
  message_text?: string;
  enrich?: boolean;
}

export interface EmployeePhishingReportRequest {
  sender_email?: string;
  reported_by_email?: string;
  subject: string;
  body_text: string;
  body_html?: string | null;
  headers?: Record<string, string>;
  channel?: ChannelType;
}

export interface DetectionSignal {
  name: string;
  weight: number;
  score: number;
  reason: string;
  metadata?: Record<string, unknown>;
}

export interface EmailAnalysisResponse {
  id: string;
  correlation_id: string;
  timestamp: string;
  created_at: string;
  channel: ChannelType;
  sender: string;
  sender_email: string;
  sender_domain: string;
  recipient: string;
  subject: string;
  risk_score: number;
  severity: SeverityType;
  verdict: VerdictType;
  action: GatewayActionType;
  summary: string;
  incident_triggered: boolean;
  incident_id: string | null;
  incident_code: string | null;
  latency_ms: number;
  urls: string[];
  attachments: EmailAttachmentDto[];
  llm_classification: Record<string, unknown>;
  enrichment: Record<string, unknown>;
  signals: DetectionSignal[];
}

export interface VerdictItem {
  id: string;
  correlation_id: string;
  sender_email: string;
  sender_domain: string;
  recipient_email: string;
  subject: string;
  channel: ChannelType;
  risk_score: number;
  verdict: VerdictType;
  action_taken: GatewayActionType;
  summary: string;
  latency_ms: number;
  analyst_label: AnalystLabelType;
  headers_meta: Record<string, unknown>;
  signals_meta: DetectionSignal[];
  incident_id: string | null;
  incident_code: string | null;
  created_at: string;
  similarity?: number;
}

export interface VerdictPage {
  items: VerdictItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface DailyTrendPoint {
  date: string;
  total: number;
  phishing?: number;
  malicious: number;
  suspicious: number;
  clean: number;
}

export interface TopDomainItem {
  domain: string;
  count: number;
}

export interface TopIpItem {
  ip: string;
  count: number;
}

export interface DashboardKpisRaw {
  window_days?: number;
  total_analyzed?: number;
  total_detections?: number;
  clean_count?: number;
  suspicious_count?: number;
  malicious_count?: number;
  by_verdict?: Record<string, number>;
  by_channel?: Record<string, number>;
  latency_avg_ms?: number;
  avg_latency_ms?: number;
  latency_p95_ms?: number;
  labeled_count?: number;
  false_positive_rate?: number | null;
  false_negative_rate?: number | null;
  accuracy_rate?: number;
  daily_trend?: DailyTrendPoint[];
  trend?: DailyTrendPoint[];
  top_domains?: TopDomainItem[];
  top_sender_domains?: TopDomainItem[];
  top_ips?: TopIpItem[];
  top_attacker_ips?: TopIpItem[];
  open_incidents?: number;
  overdue_incidents?: number;
  sla_compliance_rate?: number;
  mttr_minutes?: number | null;
  mean_time_to_triage_minutes?: number | null;
  incidents_summary?: {
    open_count?: number;
    overdue_count?: number;
    mttr_minutes?: number | null;
    mttt_minutes?: number | null;
    sla_compliance_rate?: number;
  };
  active_iocs?: number;
  active_iocs_count?: number;
  total_active_iocs?: number;
  dataset_samples?: number;
  dataset_samples_count?: number;
}

export interface NormalizedDashboardKpis {
  windowDays: number;
  totalAnalyzed: number;
  cleanCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  falsePositiveRatePct: number;
  falseNegativeRatePct: number;
  accuracyRatePct: number;
  labeledCount: number;
  latencyAvgMs: number;
  latencyP95Ms: number;
  openIncidents: number;
  overdueIncidents: number;
  mttrMinutes: number | null;
  mtttMinutes: number | null;
  slaCompliancePct: number;
  activeIocs: number;
  datasetSamples: number;
  channelDistribution: Array<{ name: ChannelType; value: number }>;
  dailyTrend: DailyTrendPoint[];
  topDomains: TopDomainItem[];
  topIps: TopIpItem[];
}

export interface IncidentEventItem {
  id: string;
  event_type: string;
  from_status: string | null;
  to_status: string | null;
  actor: string;
  note: string | null;
  created_at: string;
}

export interface IocItem {
  id: string;
  ioc_type: 'DOMAIN' | 'URL' | 'IP' | 'HASH' | 'EMAIL';
  ioc_value: string;
  list_type: 'BLACKLIST' | 'WHITELIST';
  confidence_score: number;
  source: string;
  is_active: boolean;
  expires_at?: string | null;
  created_at: string;
  similarity?: number | null;
}

export interface IncidentItem {
  id: string;
  incident_code: string;
  verdict_id: string | null;
  severity: SeverityType;
  status: IncidentStatusType;
  resolution: IncidentResolutionType | null;
  assigned_user_id: string | null;
  assigned_to: string | null;
  assigned_user_name?: string | null;
  sla_deadline: string | null;
  sla_overdue: boolean;
  is_escalated: boolean;
  created_at: string;
  resolved_at: string | null;
  sender_email: string | null;
  recipient_email?: string | null;
  subject: string | null;
  channel?: ChannelType;
  risk_score: number | null;
}

export interface IncidentDetail extends IncidentItem {
  verdict_summary: string;
  summary: string;
  summary_engine?: string;
  signals: DetectionSignal[];
  events: IncidentEventItem[];
  iocs: IocItem[];
}

export interface IncidentPage {
  items: IncidentItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface IncidentBriefingResponse {
  incident_id: string;
  incident_code: string;
  summary: string;
  recommended_actions: string[];
  compliance_controls: string[];
  engine: string;
}

export interface ManualIncidentCreatePayload {
  severity: SeverityType;
  subject: string;
  sender_email: string;
  recipient_email: string;
  summary: string;
  notes?: string;
  channel: ChannelType;
  risk_score: number;
}

export interface IocPage {
  items: IocItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface IocFuzzySearchResponse {
  query: string;
  threshold: number;
  items: IocItem[];
}

export interface IocUpsertPayload {
  ioc_type: 'DOMAIN' | 'URL' | 'IP' | 'HASH' | 'EMAIL';
  ioc_value: string;
  list_type: 'BLACKLIST' | 'WHITELIST';
  confidence_score: number;
  ttl_hours?: number;
  reason?: string;
}

export interface DatasetSampleItem {
  id: string;
  dataset_version_id?: string;
  url: string;
  url_hash?: string;
  domain: string;
  source: string;
  first_seen_at: string;
  similarity?: number;
}

export interface ThreatHuntingResponse {
  query: string;
  total_matches: number;
  verdicts: VerdictItem[];
  iocs: IocItem[];
  dataset_samples: DatasetSampleItem[];
}

export interface ScheduleItem {
  id: string;
  name: string;
  report_format: 'pdf' | 'docx' | 'xlsx';
  frequency: 'DAILY' | 'WEEKLY';
  recipients: string[];
  template: 'executive' | 'management' | 'operational' | 'compliance';
  is_active: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_status: string | null;
}

export interface DatasetInfoResponse {
  total_samples: number;
  total_versions: number;
  active_synced_iocs: number;
  latest_version: {
    id: string;
    source: string;
    sha256: string;
    created_at: string;
  } | null;
  sources: Array<{
    name: string;
    feed_url: string;
    license: string;
    schema: string;
    offline_fixture: string;
  }>;
  deduplication_policy: string;
}

export interface DatasetVersionItem {
  id: string;
  source: string;
  source_url: string | null;
  license: string | null;
  sha256: string;
  total_records: number;
  new_records: number;
  duplicate_records: number;
  invalid_records: number;
  status: string;
  triggered_by: string | null;
  created_at: string;
}

export interface SimulationCampaign {
  id: string;
  name: string;
  channel: ChannelType;
  template_subject: string;
  lure_type: string;
  target_department: string;
  status: string;
  total_targets: number;
  sent_count: number;
  opened_count: number;
  clicked_count: number;
  reported_count: number;
  click_rate: number;
  report_rate: number;
  compromise_risk: string;
  created_by: string;
  launched_at: string;
  completed_at: string | null;
  created_at: string;
}

export interface SimulationAggregateMetrics {
  total_campaigns: number;
  active_campaigns: number;
  total_targets: number;
  total_sent: number;
  total_opened: number;
  total_clicked: number;
  total_reported: number;
  overall_open_rate: number;
  overall_click_rate: number;
  overall_report_rate: number;
  overall_compromise_risk: string;
  employee_reported_phishing_count: number;
  by_department: Array<{
    department: string;
    targets: number;
    sent: number;
    clicked: number;
    reported: number;
    click_rate: number;
    report_rate: number;
    compromise_risk: string;
  }>;
}

export interface AuditLogItem {
  id: number | string;
  event_timestamp: string;
  user_email: string;
  client_ip: string | null;
  action: string;
  resource: string;
  payload: Record<string, unknown> | null;
  prev_hash: string;
  integrity_hash: string;
}

export interface AuditLogPage {
  items: AuditLogItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface AuditChainVerification {
  valid: boolean;
  checked: number;
  head_hash?: string | null;
  broken_at_id?: number | string | null;
  reason?: string | null;
  algorithm: string;
  append_only_triggers: string[];
  verified_at: string;
}

export interface ComplianceControl {
  id: string;
  title: string;
  status: string;
  evidence: string;
}

export interface ComplianceFramework {
  framework: string;
  controls: ComplianceControl[];
}

export interface CompliancePostureResponse {
  generated_at: string;
  overall_status: string;
  live_evidence: {
    rbac_users_count: number;
    active_users_count: number;
    mfa_enabled_users_count: number;
    audit_chain_valid: boolean;
    audit_entries_checked: number;
    sla_compliance_rate: number;
    mttr_minutes: number | null;
    active_iocs_count: number;
    dataset_versions_count: number;
    deduplicated_samples_count: number;
  };
  frameworks: ComplianceFramework[];
}

export interface AssistantChatResponse {
  question: string;
  answer: string;
  citations: string[];
  chunks?: Array<{
    source: string;
    heading: string;
    content: string;
    score?: number;
  }>;
  live_telemetry?: Record<string, unknown>;
  incident_context?: Record<string, unknown> | null;
  injection_detected: boolean;
  engine: string;
}

export interface UrlInvestigationResponse {
  url: string;
  normalized_url: string;
  domain: string;
  risk_score: number;
  verdict: VerdictType;
  action: GatewayActionType;
  summary: string;
  signals: DetectionSignal[];
  tool_observations: Record<string, unknown>;
  engine: string;
}

export interface LangFlowSandboxItem {
  id?: string;
  name: string;
  filename: string;
  description?: string;
  node_count?: number;
  edge_count?: number;
  nodes?: Array<Record<string, unknown>>;
  edges?: Array<Record<string, unknown>>;
  flow: Record<string, unknown>;
}

export interface LangFlowListResponse {
  count: number;
  flows: LangFlowSandboxItem[];
}
