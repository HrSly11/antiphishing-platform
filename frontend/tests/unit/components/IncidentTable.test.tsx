import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it } from 'vitest';
import RequirePermission from '../../../src/components/auth/RequirePermission';
import { PERMISSIONS, ROLE_PERMISSIONS_MAP } from '../../../src/lib/permissions';
import { useAuthStore } from '../../../src/stores/authStore';

describe('RequirePermission declarative RBAC guard', () => {
  beforeEach(() => {
    useAuthStore.getState().clearSession();
  });

  it('renders page restriction card when VIEWER accesses an AUDIT_READ view', () => {
    useAuthStore.getState().setSession({
      access_token: 'tok-v',
      refresh_token: 'ref-v',
      token_type: 'bearer',
      expires_in: 1800,
      user: {
        id: 'u-viewer',
        email: 'viewer@bancocentral.com',
        full_name: 'Elena Vargas',
        role: 'VIEWER',
        is_active: true,
        mfa_enabled: false,
        locked: false,
        failed_login_attempts: 0,
        locked_until: null,
        last_login_at: null,
        created_at: '2026-10-27T00:00:00Z',
        permissions: [...ROLE_PERMISSIONS_MAP.VIEWER],
      },
      permissions: [...ROLE_PERMISSIONS_MAP.VIEWER],
    });

    const blockedHtml = renderToStaticMarkup(
      <RequirePermission permission={PERMISSIONS.AUDIT_READ} mode="page">
        <div>SECRET_AUDIT_CONTENT</div>
      </RequirePermission>,
    );

    expect(blockedHtml).not.toContain('SECRET_AUDIT_CONTENT');
    expect(blockedHtml).toContain('Insufficient Role Permissions');
    expect(blockedHtml).toContain('VIEWER');
  });

  it('renders protected action children cleanly when role holds required permission', () => {
    useAuthStore.getState().setSession({
      access_token: 'tok-a',
      refresh_token: 'ref-a',
      token_type: 'bearer',
      expires_in: 1800,
      user: {
        id: 'u-auditor',
        email: 'auditor@bancocentral.com',
        full_name: 'Ricardo Soto',
        role: 'AUDITOR',
        is_active: true,
        mfa_enabled: false,
        locked: false,
        failed_login_attempts: 0,
        locked_until: null,
        last_login_at: null,
        created_at: '2026-10-27T00:00:00Z',
        permissions: [...ROLE_PERMISSIONS_MAP.AUDITOR],
      },
      permissions: [...ROLE_PERMISSIONS_MAP.AUDITOR],
    });

    const allowedHtml = renderToStaticMarkup(
      <RequirePermission permission={PERMISSIONS.AUDIT_READ} mode="page">
        <div>VERIFIED_AUDIT_LEDGER</div>
      </RequirePermission>,
    );

    expect(allowedHtml).toContain('VERIFIED_AUDIT_LEDGER');
  });
});
