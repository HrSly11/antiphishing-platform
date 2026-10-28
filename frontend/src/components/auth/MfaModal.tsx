import { useState } from 'react';
import { CheckCircle2, Copy, KeyRound, ShieldCheck, ShieldOff, X } from 'lucide-react';
import { apiClient, extractApiError } from '../../api/client';
import { useAuthStore } from '../../stores/authStore';
import type { MfaSetupResponse } from '../../types/domain';

interface MfaModalProps {
  open: boolean;
  onClose: () => void;
}

export default function MfaModal({ open, onClose }: MfaModalProps) {
  const user = useAuthStore((s) => s.user);
  const refreshMe = useAuthStore((s) => s.refreshMe);

  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  if (!open || !user) return null;

  const handleStartSetup = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const res = await apiClient.post<MfaSetupResponse>('/auth/mfa/setup');
      setSetupData(res.data);
      setTotpCode('');
      setMessage({
        type: 'ok',
        text: 'TOTP secret generated. Add it to Google Authenticator / Microsoft Authenticator and enter the 6-digit code below.',
      });
    } catch (err) {
      setMessage({ type: 'err', text: extractApiError(err) });
    } finally {
      setBusy(false);
    }
  };

  const handleEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await apiClient.post('/auth/mfa/enable', { totp_code: totpCode.trim() });
      await refreshMe();
      setSetupData(null);
      setTotpCode('');
      setMessage({ type: 'ok', text: 'RFC 6238 TOTP MFA is now enforced on your account.' });
    } catch (err) {
      setMessage({ type: 'err', text: extractApiError(err) });
    } finally {
      setBusy(false);
    }
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await apiClient.post('/auth/mfa/disable', {
        password: disablePassword || undefined,
        totp_code: disableCode.trim() || undefined,
      });
      await refreshMe();
      setSetupData(null);
      setDisablePassword('');
      setDisableCode('');
      setMessage({ type: 'ok', text: 'TOTP MFA has been disabled for your account.' });
    } catch (err) {
      setMessage({ type: 'err', text: extractApiError(err) });
    } finally {
      setBusy(false);
    }
  };

  const copySecret = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard unavailable
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4">
      <div className="soc-card w-full max-w-lg overflow-hidden shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-600 dark:text-blue-400">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                RFC 6238 TOTP Multi-Factor Authentication
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                PCI-DSS v4.0 Req 8.4 · {user.email}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <div className="soc-card-muted p-3.5 flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-800 dark:text-slate-200">Current MFA Posture</div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">
                Time-based One-Time Password (30-second window, SHA-1 6 digits)
              </div>
            </div>
            {user.mfa_enabled ? (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-semibold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                <ShieldCheck className="w-3.5 h-3.5" /> ENFORCED
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-semibold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                <ShieldOff className="w-3.5 h-3.5" /> NOT ENROLLED
              </span>
            )}
          </div>

          {message && (
            <div
              className={`p-3 rounded-lg border text-xs ${
                message.type === 'ok'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
                  : 'bg-red-500/10 border-red-500/30 text-red-700 dark:text-red-300'
              }`}
            >
              {message.text}
            </div>
          )}

          {!user.mfa_enabled ? (
            <div className="space-y-4">
              {!setupData ? (
                <div className="space-y-3">
                  <p className="text-slate-600 dark:text-slate-400">
                    Enroll an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, or Authy) to protect privileged SOC actions.
                  </p>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleStartSetup}
                    className="soc-btn-primary w-full"
                  >
                    {busy ? 'Generating TOTP Secret...' : '1. Generate TOTP Provisioning Secret'}
                  </button>
                </div>
              ) : (
                <form onSubmit={handleEnable} className="space-y-3">
                  <div className="soc-card-muted p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="soc-label">Base32 Secret ({setupData.issuer})</span>
                      <button
                        type="button"
                        onClick={() => copySecret(setupData.secret)}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        {copied ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        {copied ? 'Copied' : 'Copy Secret'}
                      </button>
                    </div>
                    <div className="font-mono text-sm font-bold tracking-widest text-slate-900 dark:text-white break-all select-all">
                      {setupData.secret}
                    </div>
                    <div className="pt-1 border-t border-slate-200 dark:border-slate-800">
                      <span className="soc-label mb-1">Provisioning URI (otpauth://)</span>
                      <code className="block font-mono text-[10px] text-slate-600 dark:text-slate-400 break-all">
                        {setupData.otpauth_uri}
                      </code>
                    </div>
                  </div>

                  <div>
                    <label className="soc-label mb-1">2. Verify 6-Digit Authenticator Code</label>
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]{6}"
                      maxLength={6}
                      required
                      placeholder="123456"
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="soc-input font-mono tracking-widest text-sm text-center"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => setSetupData(null)}
                      className="soc-btn-secondary"
                    >
                      Reset
                    </button>
                    <button
                      type="submit"
                      disabled={busy || totpCode.length !== 6}
                      className="soc-btn-primary"
                    >
                      {busy ? 'Verifying...' : 'Verify & Enforce MFA'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          ) : (
            <form onSubmit={handleDisable} className="space-y-3">
              <p className="text-slate-600 dark:text-slate-400">
                To disable TOTP MFA on your account, confirm your account password or provide a live 6-digit TOTP code.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="soc-label mb-1">Account Password</label>
                  <input
                    type="password"
                    placeholder="Confirm password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    className="soc-input"
                  />
                </div>
                <div>
                  <label className="soc-label mb-1">Or 6-Digit TOTP Code</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    placeholder="000000"
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="soc-input font-mono"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button type="button" onClick={onClose} className="soc-btn-secondary">
                  Close
                </button>
                <button type="submit" disabled={busy} className="soc-btn-danger">
                  {busy ? 'Disabling...' : 'Disable TOTP MFA'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
