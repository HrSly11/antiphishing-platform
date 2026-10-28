import React from 'react';
import { Lock, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { rolesWithPermission } from '../../lib/permissions';

export interface RequirePermissionProps {
  permission: string;
  /**
   * - `disable`: renders children inside a disabled/locked wrapper with clear role tooltip (default for buttons/actions)
   * - `hide`: hides children completely when unauthorized
   * - `page`: renders an enterprise RBAC access-restricted card for full views/routes
   */
  mode?: 'disable' | 'hide' | 'page';
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

export function RequirePermission({
  permission,
  mode = 'disable',
  fallback,
  children,
}: RequirePermissionProps) {
  const user = useAuthStore((s) => s.user);
  const hasPermission = useAuthStore((s) => s.hasPermission);
  const allowed = hasPermission(permission);

  if (allowed) {
    return <>{children}</>;
  }

  if (fallback !== undefined) {
    return <>{fallback}</>;
  }

  if (mode === 'hide') {
    return null;
  }

  const permittedRoles = rolesWithPermission(permission);
  const effectiveUser = user ?? useAuthStore.getState().user;
  const currentRole = effectiveUser?.role ?? 'UNAUTHENTICATED';
  const tooltip = `RBAC Restricted: requires '${permission}'. Your role (${currentRole}) is unauthorized. Allowed roles: ${permittedRoles.join(', ')}.`;

  if (mode === 'page') {
    return (
      <div className="p-6 max-w-3xl mx-auto">
        <div className="soc-card p-8 text-center space-y-4 border-amber-500/30">
          <div className="mx-auto w-12 h-12 rounded-full bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-500">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
              PCI-DSS Req 7.2 · Least-Privilege RBAC
            </span>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white pt-1">
              Insufficient Role Permissions
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 max-w-lg mx-auto">
              Your active session role (<strong className="font-mono">{currentRole}</strong>) does not
              grant the <code className="font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800">{permission}</code>{' '}
              capability required to access this module.
            </p>
          </div>
          <div className="soc-card-muted p-3 text-xs text-slate-600 dark:text-slate-400">
            Authorized roles for <code className="font-mono font-semibold">{permission}</code>:{' '}
            <span className="font-mono font-semibold text-slate-900 dark:text-slate-200">
              {permittedRoles.join(' · ')}
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <span
      title={tooltip}
      aria-disabled="true"
      className="inline-flex items-center gap-1 opacity-50 cursor-not-allowed select-none"
    >
      <span className="pointer-events-none inline-flex items-center">{children}</span>
      <Lock className="w-3 h-3 text-amber-500 shrink-0" />
    </span>
  );
}

export default RequirePermission;
