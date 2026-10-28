import { useMutation } from '@tanstack/react-query';
import { apiClient } from '../client';
import type {
  EmailAnalysisRequest,
  EmailAnalysisResponse,
  EmployeePhishingReportRequest,
  UrlAnalysisRequest,
} from '../../types/domain';

export type { EmailAnalysisRequest, EmailAnalysisResponse };

export interface AnalyzeResult {
  data: EmailAnalysisResponse;
  status: number;
  latencyMs: number;
}

export async function analyzeEmail(payload: EmailAnalysisRequest): Promise<AnalyzeResult> {
  const startedAt = performance.now();
  const res = await apiClient.post<EmailAnalysisResponse>('/detection/analyze-email', payload);
  return {
    data: res.data,
    status: res.status,
    latencyMs: Math.round(performance.now() - startedAt),
  };
}

export async function analyzeEmlFile(file: File): Promise<AnalyzeResult> {
  const startedAt = performance.now();
  const form = new FormData();
  form.append('file', file);
  const res = await apiClient.post<EmailAnalysisResponse>('/detection/analyze-eml', form);
  return {
    data: res.data,
    status: res.status,
    latencyMs: Math.round(performance.now() - startedAt),
  };
}

export async function analyzeRawEml(rawEml: string): Promise<AnalyzeResult> {
  const startedAt = performance.now();
  const res = await apiClient.post<EmailAnalysisResponse>('/detection/analyze-eml', {
    raw_eml: rawEml,
  });
  return {
    data: res.data,
    status: res.status,
    latencyMs: Math.round(performance.now() - startedAt),
  };
}

export async function analyzeUrl(payload: UrlAnalysisRequest): Promise<AnalyzeResult> {
  const startedAt = performance.now();
  const res = await apiClient.post<EmailAnalysisResponse>('/detection/analyze-url', payload);
  return {
    data: res.data,
    status: res.status,
    latencyMs: Math.round(performance.now() - startedAt),
  };
}

export async function reportEmployeePhishing(
  payload: EmployeePhishingReportRequest,
): Promise<AnalyzeResult> {
  const startedAt = performance.now();
  const res = await apiClient.post<EmailAnalysisResponse>('/detection/report-phishing', payload);
  return {
    data: res.data,
    status: res.status,
    latencyMs: Math.round(performance.now() - startedAt),
  };
}

export async function checkApiHealth(): Promise<{
  healthy: boolean;
  dbReady: boolean;
  service?: string;
}> {
  try {
    const [hRes, rRes] = await Promise.allSettled([
      apiClient.get('/health'),
      apiClient.get('/ready'),
    ]);
    const healthy = hRes.status === 'fulfilled' && hRes.value.status === 200;
    const dbReady = rRes.status === 'fulfilled' && rRes.value.status === 200;
    const service =
      hRes.status === 'fulfilled' ? String(hRes.value.data?.service ?? 'Antiphishing API') : undefined;
    return { healthy, dbReady, service };
  } catch {
    return { healthy: false, dbReady: false };
  }
}

export const useAnalyze = () => useMutation({ mutationFn: analyzeEmail });
