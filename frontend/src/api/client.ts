import axios, { isAxiosError, type InternalAxiosRequestConfig } from 'axios';
import { useAuthStore } from '../stores/authStore';
import type { TokenResponse } from '../types/domain';

interface RetriableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

export const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 25000,
});

let refreshInFlight: Promise<string | null> | null = null;

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().access_token;
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error?.config as RetriableRequestConfig | undefined;
    const status = error?.response?.status;
    const url = String(original?.url ?? '');

    const isAuthEndpoint =
      url.includes('/auth/login') || url.includes('/auth/refresh') || url.includes('/auth/logout');

    if (status === 401 && original && !original._retry && !isAuthEndpoint) {
      const { refresh_token, setSession, clearSession } = useAuthStore.getState();
      if (!refresh_token) {
        clearSession();
        return Promise.reject(error);
      }

      original._retry = true;

      if (!refreshInFlight) {
        refreshInFlight = axios
          .post<TokenResponse>('/api/v1/auth/refresh', { refresh_token })
          .then((res) => {
            setSession(res.data);
            return res.data.access_token;
          })
          .catch(() => {
            clearSession();
            return null;
          })
          .finally(() => {
            refreshInFlight = null;
          });
      }

      const nextToken = await refreshInFlight;
      if (nextToken) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${nextToken}`;
        return apiClient(original);
      }
    }

    return Promise.reject(error);
  },
);

export function extractApiError(err: unknown): string {
  if (isAxiosError(err)) {
    const data = err.response?.data as
      | { detail?: unknown; message?: string; error?: string }
      | undefined;
    if (data) {
      if (typeof data.detail === 'string') return data.detail;
      if (Array.isArray(data.detail)) {
        return data.detail
          .map((item) => {
            if (typeof item === 'string') return item;
            if (item && typeof item === 'object' && 'msg' in item) {
              const loc = Array.isArray((item as { loc?: unknown[] }).loc)
                ? (item as { loc: unknown[] }).loc.slice(1).join('.')
                : '';
              const msg = String((item as { msg: unknown }).msg);
              return loc ? `${loc}: ${msg}` : msg;
            }
            return JSON.stringify(item);
          })
          .join('; ');
      }
      if (typeof data.message === 'string') return data.message;
      if (typeof data.error === 'string') return data.error;
    }
    if (err.message) return err.message;
  }
  if (err instanceof Error) return err.message;
  return 'Unexpected API error occurred';
}
