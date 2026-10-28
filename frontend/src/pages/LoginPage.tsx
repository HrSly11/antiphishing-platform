import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Building2,
  CheckCircle2,
  Globe,
  KeyRound,
  Lock,
  Moon,
  Shield,
  Sparkles,
  Sun,
  UserCheck,
} from 'lucide-react';
import { apiClient } from '../api/client';
import { translateText } from '../lib/i18n';
import { DEMO_ROLE_ACCOUNTS, type DemoRoleAccount } from '../lib/permissions';
import { useAuthStore } from '../stores/authStore';
import { useLanguageStore } from '../stores/languageStore';
import { useThemeStore } from '../stores/themeStore';
import type { SsoProvidersResponse } from '../types/domain';

export default function LoginPage() {
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const login = useAuthStore((s) => s.login);

  const theme = useThemeStore((s) => s.theme);
  const toggleTheme = useThemeStore((s) => s.toggleTheme);
  const lang = useLanguageStore((s) => s.lang);
  const toggleLang = useLanguageStore((s) => s.toggleLang);
  const tr = (text: string) => translateText(text, lang);

  const [email, setEmail] = useState(DEMO_ROLE_ACCOUNTS[0].email);
  const [password, setPassword] = useState(DEMO_ROLE_ACCOUNTS[0].password);
  const [totpCode, setTotpCode] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ssoData, setSsoData] = useState<SsoProvidersResponse | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    apiClient
      .get<SsoProvidersResponse>('/auth/sso/providers')
      .then((res) => setSsoData(res.data))
      .catch(() => setSsoData(null));
  }, []);

  const handleQuickFill = (acc: DemoRoleAccount) => {
    setEmail(acc.email);
    setPassword(acc.password);
    setTotpCode('');
    setMfaRequired(false);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    const outcome = await login(email, password, mfaRequired ? totpCode : undefined);
    setSubmitting(false);

    if (outcome.ok) {
      navigate('/dashboard', { replace: true });
      return;
    }

    if (outcome.mfaRequired) {
      setMfaRequired(true);
    }
    setError(outcome.error ?? 'Authentication failed.');
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* Top Bar */}
      <header className="px-6 py-4 flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/70 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white flex items-center justify-center shadow-md">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="font-bold text-sm sm:text-base tracking-tight text-slate-900 dark:text-white">
              {tr('SentinelBank Anti-Phishing SOC')}
            </span>
            <span className="ml-2 text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-700 dark:text-blue-300 border border-blue-500/30">
              PCI-DSS v4.0 · ISO 27001:2022
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={toggleLang}
            className="soc-btn-secondary font-mono text-xs"
            title={
              lang === 'es'
                ? 'Cambiar idioma a Inglés (Switch to English)'
                : 'Switch language to Spanish (Cambiar a Español)'
            }
          >
            <Globe className="w-3.5 h-3.5 text-blue-500" />
            <span className={lang === 'es' ? 'font-bold text-blue-600 dark:text-blue-400' : 'opacity-60'}>
              ES (Español)
            </span>
            <span className="opacity-40">|</span>
            <span className={lang === 'en' ? 'font-bold text-blue-600 dark:text-blue-400' : 'opacity-60'}>
              EN (English)
            </span>
          </button>

          <button type="button" onClick={toggleTheme} className="soc-btn-secondary">
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            <span>{theme === 'dark' ? tr('Light Executive') : tr('Dark SOC')}</span>
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <div className="flex-1 max-w-6xl w-full mx-auto px-4 py-8 lg:py-12 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left: Login Form + Enterprise SSO Readiness */}
        <div className="lg:col-span-5 space-y-5">
          <div className="soc-card p-6 sm:p-7 space-y-5 shadow-lg">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
                <Lock className="w-3.5 h-3.5" />
                Argon2id + JWT Rotation + RFC 6238 TOTP
              </div>
              <h1 className="text-xl font-bold text-slate-900 dark:text-white">
                {tr('SOC Operator Sign-In')}
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {tr('Authenticate with your institutional BancoCentral credentials or select a 1-click RBAC evaluation profile.')}
              </p>
            </div>

            {error && (
              <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
                {tr(error)}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="soc-label mb-1">{tr('Institutional Email')}</label>
                <input
                  type="email"
                  required
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@bancocentral.com"
                  className="soc-input"
                />
              </div>

              <div>
                <label className="soc-label mb-1">{tr('Password')}</label>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="soc-input"
                />
              </div>

              {mfaRequired && (
                <div className="p-3.5 rounded-xl border border-blue-500/40 bg-blue-500/10 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-blue-700 dark:text-blue-300">
                    <KeyRound className="w-4 h-4" />
                    {tr('6-Digit TOTP Authenticator Verification')}
                  </div>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    required
                    autoFocus
                    placeholder="000000"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="soc-input font-mono text-center text-base tracking-[0.35em]"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="soc-btn-primary w-full py-2.5 text-sm"
              >
                <UserCheck className="w-4 h-4" />
                {submitting
                  ? tr('Verifying Credentials...')
                  : mfaRequired
                    ? tr('Verify MFA & Enter SOC')
                    : tr('Sign In to SentinelBank SOC')}
              </button>
            </form>

            {/* Enterprise Federation Readiness Badge */}
            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="soc-label flex items-center gap-1.5">
                  <Building2 className="w-3.5 h-3.5 text-blue-500" />
                  {tr('Enterprise Identity Federation')}
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400">
                  {ssoData?.primary_mode ?? 'local-argon2id'}
                </span>
              </div>

              <div className="grid grid-cols-1 gap-1.5">
                {(ssoData?.providers ?? [
                  { provider: 'Local Argon2id + TOTP', enabled: true, status: 'ACTIVE' },
                  { provider: 'SAML 2.0 / OIDC Federation', enabled: false, status: 'ADAPTER_READY' },
                  { provider: 'Corporate LDAPS Active Directory', enabled: false, status: 'ADAPTER_READY' },
                ]).map((prov, idx) => {
                  const name = String(prov.provider ?? prov.name ?? `Provider ${idx + 1}`);
                  const statusLabel = String(
                    prov.status ?? (prov.enabled ? 'ACTIVE' : 'ADAPTER_READY'),
                  );
                  return (
                    <div
                      key={name}
                      className="soc-card-muted px-3 py-2 flex items-center justify-between text-[11px]"
                    >
                      <span className="font-medium text-slate-700 dark:text-slate-300">{tr(name)}</span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] border ${
                          prov.enabled
                            ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                            : 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/25'
                        }`}
                      >
                        {tr(statusLabel)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Right: 1-Click Seeded RBAC Role Quick-Fill Cards */}
        <div className="lg:col-span-7 space-y-4">
          <div className="soc-card p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="inline-flex items-center gap-1.5 text-[11px] font-mono font-semibold text-purple-600 dark:text-purple-400">
                  <Sparkles className="w-3.5 h-3.5" />
                  {tr('1-Click Evaluator RBAC Profiles (Seeded in PostgreSQL)')}
                </div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white mt-0.5">
                  {tr('Test All 5 Banking Security Roles Instantly')}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {tr('Click any card below to pre-fill credentials from')} <code>seed.py</code> {tr('and verify granular least-privilege RBAC across modules.')}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {DEMO_ROLE_ACCOUNTS.map((acc) => {
                const selected = email.toLowerCase() === acc.email.toLowerCase();
                return (
                  <button
                    key={acc.role}
                    type="button"
                    onClick={() => handleQuickFill(acc)}
                    className={`text-left p-4 rounded-xl border transition space-y-2 ${
                      selected
                        ? 'border-blue-500 bg-blue-500/5 dark:bg-blue-500/10 ring-2 ring-blue-500/20'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 hover:border-blue-400'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${acc.badgeColor}`}
                      >
                        {acc.role}
                      </span>
                      {selected && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                          <CheckCircle2 className="w-3.5 h-3.5" /> {tr('Selected')}
                        </span>
                      )}
                    </div>
                    <div>
                      <div className="text-xs font-bold text-slate-900 dark:text-white">
                        {acc.persona} — {tr(acc.title)}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                        {acc.email}
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">
                      {tr(acc.summary)}
                    </p>
                  </button>
                );
              })}
            </div>

            <div className="soc-card-muted p-3.5 text-[11px] text-slate-600 dark:text-slate-400 flex flex-wrap items-center justify-between gap-2">
              <span>
                {tr('Account Lockout Policy:')} <strong>{tr('5 failed attempts → 15 min lock')}</strong> {tr('(PCI-DSS Req 8.3.4)')}
              </span>
              <span className="font-mono text-slate-700 dark:text-slate-300">
                {tr('SHA-256 Append-Only Audit Active')}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
