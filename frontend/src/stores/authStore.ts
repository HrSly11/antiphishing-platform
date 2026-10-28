import { create } from 'zustand';
import { isAxiosError } from 'axios';
import { apiClient, extractApiError } from '../api/client';
import { ROLE_PERMISSIONS_MAP } from '../lib/permissions';
import type { RoleName, TokenResponse, UserProfile } from '../types/domain';

export const AUTH_STORAGE_KEY = 'sentinelbank_soc_auth_v1';

interface PersistedAuthSnapshot {
  access_token: string | null;
  refresh_token: string | null;
  user: UserProfile | null;
}

const memoryAuthStorage = new Map<string, string>();

function readPersistedAuth(): PersistedAuthSnapshot {
  try {
    const raw =
      typeof window !== 'undefined' &&
      window.localStorage &&
      typeof window.localStorage.getItem === 'function'
        ? window.localStorage.getItem(AUTH_STORAGE_KEY)
        : (memoryAuthStorage.get(AUTH_STORAGE_KEY) ?? null);
    if (!raw) return { access_token: null, refresh_token: null, user: null };
    const parsed = JSON.parse(raw) as Partial<PersistedAuthSnapshot>;
    return {
      access_token: typeof parsed.access_token === 'string' ? parsed.access_token : null,
      refresh_token: typeof parsed.refresh_token === 'string' ? parsed.refresh_token : null,
      user: parsed.user ?? null,
    };
  } catch {
    return { access_token: null, refresh_token: null, user: null };
  }
}

function writePersistedAuth(snapshot: PersistedAuthSnapshot): void {
  const serialized = JSON.stringify(snapshot);
  try {
    if (
      typeof window !== 'undefined' &&
      window.localStorage &&
      typeof window.localStorage.setItem === 'function'
    ) {
      if (!snapshot.access_token && !snapshot.refresh_token && !snapshot.user) {
        window.localStorage.removeItem(AUTH_STORAGE_KEY);
      } else {
        window.localStorage.setItem(AUTH_STORAGE_KEY, serialized);
      }
      return;
    }
  } catch {
    // Fallback to memory store in non-DOM tests
  }
  if (!snapshot.access_token && !snapshot.refresh_token && !snapshot.user) {
    memoryAuthStorage.delete(AUTH_STORAGE_KEY);
  } else {
    memoryAuthStorage.set(AUTH_STORAGE_KEY, serialized);
  }
}

export interface LoginOutcome {
  ok: boolean;
  mfaRequired?: boolean;
  error?: string;
}

export interface AuthState {
  access_token: string | null;
  refresh_token: string | null;
  user: UserProfile | null;
  isAuthenticated: boolean;
  setSession: (bundle: TokenResponse) => void;
  setUser: (user: UserProfile) => void;
  clearSession: () => void;
  hasPermission: (perm: string) => boolean;
  hasAnyPermission: (perms: string[]) => boolean;
  login: (email: string, password: string, totpCode?: string) => Promise<LoginOutcome>;
  logout: () => Promise<void>;
  refreshMe: () => Promise<UserProfile | null>;
}

const initial = readPersistedAuth();

export const useAuthStore = create<AuthState>((set, get) => ({
  access_token: initial.access_token,
  refresh_token: initial.refresh_token,
  user: initial.user,
  isAuthenticated: Boolean(initial.access_token && initial.user),

  setSession: (bundle: TokenResponse) => {
    const normalizedUser: UserProfile = {
      ...bundle.user,
      permissions:
        bundle.user.permissions && bundle.user.permissions.length > 0
          ? bundle.user.permissions
          : bundle.permissions && bundle.permissions.length > 0
            ? bundle.permissions
            : [...(ROLE_PERMISSIONS_MAP[bundle.user.role] ?? [])],
    };
    const snapshot: PersistedAuthSnapshot = {
      access_token: bundle.access_token,
      refresh_token: bundle.refresh_token,
      user: normalizedUser,
    };
    writePersistedAuth(snapshot);
    set({
      access_token: bundle.access_token,
      refresh_token: bundle.refresh_token,
      user: normalizedUser,
      isAuthenticated: true,
    });
  },

  setUser: (user: UserProfile) => {
    const current = get();
    const snapshot: PersistedAuthSnapshot = {
      access_token: current.access_token,
      refresh_token: current.refresh_token,
      user,
    };
    writePersistedAuth(snapshot);
    set({ user, isAuthenticated: Boolean(current.access_token && user) });
  },

  clearSession: () => {
    writePersistedAuth({ access_token: null, refresh_token: null, user: null });
    set({
      access_token: null,
      refresh_token: null,
      user: null,
      isAuthenticated: false,
    });
  },

  hasPermission: (perm: string) => {
    const u = get().user;
    if (!u) return false;
    if (u.role === ('ADMIN' as RoleName)) return true;
    const explicit = u.permissions && u.permissions.length > 0
      ? u.permissions
      : (ROLE_PERMISSIONS_MAP[u.role] ?? []);
    return explicit.includes(perm);
  },

  hasAnyPermission: (perms: string[]) => {
    const check = get().hasPermission;
    return perms.some((p) => check(p));
  },

  login: async (email: string, password: string, totpCode?: string): Promise<LoginOutcome> => {
    try {
      const payload: Record<string, string> = {
        email: email.trim(),
        password,
      };
      if (totpCode && totpCode.trim()) {
        payload.totp_code = totpCode.trim();
      }
      const res = await apiClient.post<TokenResponse>('/auth/login', payload);
      get().setSession(res.data);
      return { ok: true };
    } catch (err) {
      if (isAxiosError(err)) {
        const mfaHeader =
          err.response?.headers?.['x-mfa-required'] ?? err.response?.headers?.['X-MFA-Required'];
        const detailStr = extractApiError(err);
        if (
          String(mfaHeader).toLowerCase() === 'true' ||
          detailStr.toLowerCase().includes('mfa code required')
        ) {
          return {
            ok: false,
            mfaRequired: true,
            error: totpCode
              ? 'Invalid 6-digit TOTP authenticator code. Please try again.'
              : 'Multi-Factor Authentication (RFC 6238 TOTP) is active for this account.',
          };
        }
      }
      return { ok: false, error: extractApiError(err) };
    }
  },

  logout: async () => {
    try {
      if (get().access_token) {
        await apiClient.post('/auth/logout');
      }
    } catch {
      // Ignore logout network error and always clear local credentials
    } finally {
      get().clearSession();
    }
  },

  refreshMe: async () => {
    if (!get().access_token) return null;
    try {
      const res = await apiClient.get<UserProfile>('/auth/me');
      get().setUser(res.data);
      return res.data;
    } catch {
      return null;
    }
  },
}));
