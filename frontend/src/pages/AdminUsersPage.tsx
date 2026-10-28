import { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  KeyRound,
  LockOpen,
  Plus,
  RefreshCw,
  ShieldCheck,
  UserPlus,
  Users,
  X,
  XCircle,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import {
  evaluatePasswordPolicy,
  formatUtcDateTime,
  getRoleBadgeClasses,
} from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import { useAuthStore } from '../stores/authStore';
import type { RbacMatrixResponse, RoleName, UserProfile } from '../types/domain';

const ALL_ROLES: RoleName[] = ['ADMIN', 'SOC_L2', 'SOC_L1', 'AUDITOR', 'VIEWER'];

export default function AdminUsersPage() {
  const currentUser = useAuthStore((s) => s.user);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [matrix, setMatrix] = useState<RbacMatrixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);

  // Create User Modal
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newUser, setNewUser] = useState({
    email: '',
    full_name: '',
    role: 'SOC_L1' as RoleName,
    password: '',
  });

  const loadUsersAndMatrix = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [uRes, mRes] = await Promise.all([
        apiClient.get<UserProfile[]>('/users'),
        apiClient.get<RbacMatrixResponse>('/users/roles'),
      ]);
      setUsers(uRes.data);
      setMatrix(mRes.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUsersAndMatrix();
  }, [loadUsersAndMatrix]);

  const pwdCheck = evaluatePasswordPolicy(newUser.password);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pwdCheck.isValid) return;
    setCreating(true);
    setError(null);
    setBanner(null);
    try {
      const res = await apiClient.post<UserProfile>('/users', newUser);
      setBanner(`Created user account '${res.data.email}' with role ${res.data.role}.`);
      setCreateOpen(false);
      setNewUser({ email: '', full_name: '', role: 'SOC_L1', password: '' });
      await loadUsersAndMatrix();
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setCreating(false);
    }
  };

  const handlePatchUser = async (
    userId: string,
    patch: Record<string, unknown>,
    successText: string,
  ) => {
    setError(null);
    setBanner(null);
    try {
      await apiClient.patch(`/users/${userId}`, patch);
      setBanner(successText);
      await loadUsersAndMatrix();
    } catch (err) {
      setError(extractApiError(err));
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.USERS_READ} mode="page">
        <div className="soc-card p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-purple-600 dark:text-purple-400">
              <Users className="w-3.5 h-3.5" />
              PCI-DSS REQ 7.2 &amp; 8.3 · GRANULAR RBAC, LOCKOUT &amp; MFA POSTURE
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              SOC Users, Account Lockouts &amp; Role Matrix
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Manage platform accounts, enforce 12+ character Argon2id password complexity, unlock brute-forced accounts, and audit the 15-permission RBAC matrix.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button type="button" onClick={() => void loadUsersAndMatrix()} className="soc-btn-secondary">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            <RequirePermission permission={PERMISSIONS.USERS_WRITE} mode="disable">
              <button
                type="button"
                onClick={() => setCreateOpen(true)}
                className="soc-btn-primary"
              >
                <UserPlus className="w-4 h-4" />
                Create User
              </button>
            </RequirePermission>
          </div>
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

        {/* Users Table */}
        <div className="soc-card overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">
              Platform Accounts ({users.length})
            </h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                  <th className="p-3.5">Operator / Email</th>
                  <th className="p-3.5">RBAC Role</th>
                  <th className="p-3.5">Status / MFA</th>
                  <th className="p-3.5">Lockout / Last Login</th>
                  <th className="p-3.5 text-right">Administrative Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                {users.map((u) => {
                  const isSelf = currentUser?.id === u.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                      <td className="p-3.5">
                        <div className="font-bold text-slate-900 dark:text-white">
                          {u.full_name}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">{u.email}</div>
                      </td>
                      <td className="p-3.5">
                        <RequirePermission permission={PERMISSIONS.USERS_WRITE} mode="disable">
                          <select
                            disabled={isSelf}
                            value={u.role}
                            onChange={(e) =>
                              void handlePatchUser(
                                u.id,
                                { role: e.target.value },
                                `Updated role for ${u.email} to ${e.target.value}.`,
                              )
                            }
                            className={`soc-input w-32 font-mono font-bold py-1 ${getRoleBadgeClasses(
                              u.role,
                            )}`}
                          >
                            {ALL_ROLES.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        </RequirePermission>
                      </td>
                      <td className="p-3.5">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                              u.is_active
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                                : 'bg-slate-500/15 text-slate-500 border-slate-500/30'
                            }`}
                          >
                            {u.is_active ? 'ACTIVE' : 'DISABLED'}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] border inline-flex items-center gap-1 ${
                              u.mfa_enabled
                                ? 'bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30'
                                : 'bg-slate-500/10 text-slate-500 border-slate-500/20'
                            }`}
                          >
                            <KeyRound className="w-2.5 h-2.5" />
                            {u.mfa_enabled ? 'TOTP ON' : 'MFA OFF'}
                          </span>
                        </div>
                      </td>
                      <td className="p-3.5 font-mono text-[11px] text-slate-500">
                        {u.locked ? (
                          <span className="text-red-600 dark:text-red-400 font-bold">
                            LOCKED until {formatUtcDateTime(u.locked_until)}
                          </span>
                        ) : (
                          <div>Failed attempts: {u.failed_login_attempts}/5</div>
                        )}
                        <div className="text-[10px]">
                          Last login: {formatUtcDateTime(u.last_login_at)}
                        </div>
                      </td>
                      <td className="p-3.5 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          {(u.locked || u.failed_login_attempts > 0) && (
                            <RequirePermission permission={PERMISSIONS.USERS_WRITE} mode="disable">
                              <button
                                type="button"
                                onClick={() =>
                                  void handlePatchUser(
                                    u.id,
                                    { unlock: true },
                                    `Unlocked account ${u.email} and reset failed login counter.`,
                                  )
                                }
                                className="soc-btn-secondary py-1 px-2 text-[10px]"
                              >
                                <LockOpen className="w-3 h-3" /> Unlock
                              </button>
                            </RequirePermission>
                          )}

                          {!isSelf && (
                            <RequirePermission permission={PERMISSIONS.USERS_WRITE} mode="disable">
                              <button
                                type="button"
                                onClick={() =>
                                  void handlePatchUser(
                                    u.id,
                                    { is_active: !u.is_active },
                                    `${u.is_active ? 'Deactivated' : 'Activated'} user ${u.email}.`,
                                  )
                                }
                                className="soc-btn-secondary py-1 px-2 text-[10px]"
                              >
                                {u.is_active ? 'Deactivate' : 'Activate'}
                              </button>
                            </RequirePermission>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Granular RBAC Matrix */}
        {matrix && (
          <div className="soc-card overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-blue-500" />
                Granular Role-to-Permission Matrix ({matrix.all_permissions.length} Capabilities)
              </h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                    <th className="p-3">Permission Capability</th>
                    {ALL_ROLES.map((role) => (
                      <th key={role} className="p-3 text-center font-mono">
                        {role}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                  {matrix.all_permissions.map((perm) => (
                    <tr key={perm} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                      <td className="p-3 font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {perm}
                      </td>
                      {ALL_ROLES.map((role) => {
                        const roleEntry = matrix.roles.find((r) => r.role === role);
                        const granted = roleEntry?.permissions.includes(perm) ?? false;
                        return (
                          <td key={role} className="p-3 text-center">
                            {granted ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-500 inline-block" />
                            ) : (
                              <XCircle className="w-4 h-4 text-slate-300 dark:text-slate-700 inline-block" />
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Create User Modal with Live Password Policy Checklist */}
        {createOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4">
            <div className="soc-card w-full max-w-md overflow-hidden shadow-2xl">
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Provision New SOC Operator Account
                </h3>
                <button
                  type="button"
                  onClick={() => setCreateOpen(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <form onSubmit={handleCreateUser} className="p-5 space-y-3 text-xs">
                <div>
                  <label className="soc-label mb-1">Full Name &amp; Title</label>
                  <input
                    type="text"
                    required
                    placeholder="Sofia Morales — SOC L1 Analyst"
                    value={newUser.full_name}
                    onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })}
                    className="soc-input"
                  />
                </div>

                <div>
                  <label className="soc-label mb-1">Institutional Email</label>
                  <input
                    type="email"
                    required
                    placeholder="smorales@bancocentral.com"
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    className="soc-input font-mono"
                  />
                </div>

                <div>
                  <label className="soc-label mb-1">Assigned RBAC Role</label>
                  <select
                    value={newUser.role}
                    onChange={(e) =>
                      setNewUser({ ...newUser, role: e.target.value as RoleName })
                    }
                    className="soc-input font-mono"
                  >
                    {ALL_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="soc-label mb-1">Initial Password (Argon2id)</label>
                  <input
                    type="password"
                    required
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    placeholder="Min 12 chars, upper, lower, digit, symbol"
                    className="soc-input font-mono"
                  />
                </div>

                {/* Live PCI-DSS 8.3 Password Complexity Checklist */}
                <div className="soc-card-muted p-3 space-y-1 text-[11px]">
                  <div className="soc-label mb-1">PCI-DSS 8.3 Password Policy</div>
                  {[
                    { ok: pwdCheck.minLength, label: 'At least 12 characters' },
                    { ok: pwdCheck.hasUpper, label: 'At least 1 uppercase letter (A-Z)' },
                    { ok: pwdCheck.hasLower, label: 'At least 1 lowercase letter (a-z)' },
                    { ok: pwdCheck.hasDigit, label: 'At least 1 numeric digit (0-9)' },
                    { ok: pwdCheck.hasSpecial, label: 'At least 1 special symbol (!@#$%^&*)' },
                  ].map((rule) => (
                    <div
                      key={rule.label}
                      className={`flex items-center gap-1.5 ${
                        rule.ok
                          ? 'text-emerald-600 dark:text-emerald-400 font-semibold'
                          : 'text-slate-500'
                      }`}
                    >
                      {rule.ok ? (
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5" />
                      )}
                      <span>{rule.label}</span>
                    </div>
                  ))}
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setCreateOpen(false)}
                    className="soc-btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating || !pwdCheck.isValid}
                    className="soc-btn-primary"
                  >
                    <Plus className="w-4 h-4" />
                    {creating ? 'Creating...' : 'Create Account'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </RequirePermission>
    </div>
  );
}
