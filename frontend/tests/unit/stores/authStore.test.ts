import { beforeEach, describe, expect, it } from 'vitest';
import {
  DEMO_ROLE_ACCOUNTS,
  PERMISSIONS,
  ROLE_PERMISSIONS_MAP,
} from '../../../src/lib/permissions';
import { useAuthStore } from '../../../src/stores/authStore';
import type { RoleName, UserProfile } from '../../../src/types/domain';

function makeUser(role: RoleName): UserProfile {
  return {
    id: `uid-${role.toLowerCase()}`,
    email: `${role.toLowerCase()}@bancocentral.com`,
    full_name: `Test ${role}`,
    role,
    is_active: true,
    mfa_enabled: false,
    locked: false,
    failed_login_attempts: 0,
    locked_until: null,
    last_login_at: null,
    created_at: '2026-10-27T00:00:00Z',
    permissions: [...ROLE_PERMISSIONS_MAP[role]],
  };
}

describe('authStore RBAC & seeded demo accounts', () => {
  beforeEach(() => {
    useAuthStore.getState().clearSession();
  });

  it('grants ADMIN all 15 platform capabilities', () => {
    const admin = makeUser('ADMIN');
    useAuthStore.getState().setSession({
      access_token: 'tok-admin',
      refresh_token: 'ref-admin',
      token_type: 'bearer',
      expires_in: 1800,
      user: admin,
      permissions: admin.permissions,
    });

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.hasPermission(PERMISSIONS.USERS_WRITE)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.DATASET_ADMIN)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.IOCS_WRITE)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.AUDIT_READ)).toBe(true);
  });

  it('enforces SOC_L1 triage scope while denying administrative mutations', () => {
    const l1 = makeUser('SOC_L1');
    useAuthStore.getState().setSession({
      access_token: 'tok-l1',
      refresh_token: 'ref-l1',
      token_type: 'bearer',
      expires_in: 1800,
      user: l1,
      permissions: l1.permissions,
    });

    const state = useAuthStore.getState();
    expect(state.hasPermission(PERMISSIONS.DETECTION_ANALYZE)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.INCIDENTS_WRITE)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.HUNTING_READ)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.IOCS_WRITE)).toBe(false);
    expect(state.hasPermission(PERMISSIONS.USERS_WRITE)).toBe(false);
    expect(state.hasPermission(PERMISSIONS.DATASET_ADMIN)).toBe(false);
  });

  it('restricts VIEWER strictly to executive read-only permissions', () => {
    const viewer = makeUser('VIEWER');
    useAuthStore.getState().setSession({
      access_token: 'tok-viewer',
      refresh_token: 'ref-viewer',
      token_type: 'bearer',
      expires_in: 1800,
      user: viewer,
      permissions: viewer.permissions,
    });

    const state = useAuthStore.getState();
    expect(state.hasPermission(PERMISSIONS.DASHBOARD_READ)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.REPORTS_READ)).toBe(true);
    expect(state.hasPermission(PERMISSIONS.INCIDENTS_WRITE)).toBe(false);
    expect(state.hasPermission(PERMISSIONS.AUDIT_READ)).toBe(false);
    expect(state.hasPermission(PERMISSIONS.HUNTING_READ)).toBe(false);
    expect(state.hasPermission(PERMISSIONS.USERS_READ)).toBe(false);
  });

  it('exposes all 5 seeded BancoCentral evaluation accounts matching seed.py', () => {
    expect(DEMO_ROLE_ACCOUNTS).toHaveLength(5);
    const roles = DEMO_ROLE_ACCOUNTS.map((a) => a.role);
    expect(roles).toEqual(['ADMIN', 'SOC_L2', 'SOC_L1', 'AUDITOR', 'VIEWER']);
    expect(DEMO_ROLE_ACCOUNTS[0].email).toBe('admin@bancocentral.com');
  });
});
