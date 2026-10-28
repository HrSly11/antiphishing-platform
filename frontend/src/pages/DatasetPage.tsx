import { useCallback, useEffect, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  CloudDownload,
  Database,
  FileCheck2,
  Hash,
  RefreshCw,
  Search,
} from 'lucide-react';
import { apiClient, extractApiError } from '../api/client';
import RequirePermission from '../components/auth/RequirePermission';
import { formatUtcDateTime } from '../lib/formatters';
import { PERMISSIONS } from '../lib/permissions';
import type {
  DatasetInfoResponse,
  DatasetSampleItem,
  DatasetVersionItem,
} from '../types/domain';

interface SamplesPage {
  items: DatasetSampleItem[];
  total: number;
  page: number;
  page_size: number;
}

export default function DatasetPage() {
  const [info, setInfo] = useState<DatasetInfoResponse | null>(null);
  const [versions, setVersions] = useState<DatasetVersionItem[]>([]);
  const [samples, setSamples] = useState<SamplesPage | null>(null);

  const [samplePage, setSamplePage] = useState(1);
  const [sourceFilter, setSourceFilter] = useState('');
  const [searchQ, setSearchQ] = useState('');

  const [loading, setLoading] = useState(true);
  const [ingestingSource, setIngestingSource] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);

  const loadDatasetGovernance = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [infoRes, verRes] = await Promise.all([
        apiClient.get<DatasetInfoResponse>('/dataset/info'),
        apiClient.get<DatasetVersionItem[]>('/dataset/versions', { params: { limit: 20 } }),
      ]);
      setInfo(infoRes.data);
      setVersions(verRes.data);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSamples = useCallback(async () => {
    try {
      const params: Record<string, string | number> = {
        page: samplePage,
        page_size: 12,
      };
      if (sourceFilter) params.source = sourceFilter;
      if (searchQ.trim()) params.q = searchQ.trim();
      const res = await apiClient.get<SamplesPage>('/dataset/samples', { params });
      setSamples(res.data);
    } catch (err) {
      setError(extractApiError(err));
    }
  }, [samplePage, sourceFilter, searchQ]);

  useEffect(() => {
    void loadDatasetGovernance();
  }, [loadDatasetGovernance]);

  useEffect(() => {
    void loadSamples();
  }, [loadSamples]);

  const triggerIngest = async (source: string, preferLive: boolean) => {
    setIngestingSource(source + String(preferLive));
    setError(null);
    setBanner(null);
    try {
      const res = await apiClient.post<{
        source: string;
        sha256: string;
        total_rows: number;
        new_rows: number;
        duplicate_rows: number;
      }>('/dataset/ingest', {
        source,
        prefer_live: preferLive,
        sync_blacklist: true,
      });
      setBanner(
        `ETL Ingest [${res.data.source}] completed: total=${res.data.total_rows}, new=${res.data.new_rows}, duplicates=${res.data.duplicate_rows}, sha256=${res.data.sha256.slice(0, 16)}...`,
      );
      await Promise.all([loadDatasetGovernance(), loadSamples()]);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setIngestingSource(null);
    }
  };

  const totalSamplePages = Math.max(1, Math.ceil((samples?.total ?? 0) / 12));

  return (
    <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      <RequirePermission permission={PERMISSIONS.DATASET_READ} mode="page">
        {/* Header & 1-Click ETL Controls */}
        <div className="soc-card p-5 sm:p-6 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-semibold text-blue-600 dark:text-blue-400">
              <Database className="w-3.5 h-3.5" />
              OPENPHISH &amp; PHISHTANK PUBLIC DATASET GOVERNANCE · SHA-256 LINEAGE
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Public Phishing Dataset &amp; Idempotent ETL Pipeline
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {info?.deduplication_policy ??
                'Normalized URL SHA-256 deduplication with immutable feed payload hashes.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <RequirePermission permission={PERMISSIONS.DATASET_ADMIN} mode="disable">
              <button
                type="button"
                disabled={ingestingSource !== null}
                onClick={() => void triggerIngest('openphish_sample', false)}
                className="soc-btn-secondary"
              >
                <FileCheck2 className="w-3.5 h-3.5" />
                Ingest OpenPhish Fixture
              </button>
            </RequirePermission>

            <RequirePermission permission={PERMISSIONS.DATASET_ADMIN} mode="disable">
              <button
                type="button"
                disabled={ingestingSource !== null}
                onClick={() => void triggerIngest('phishtank_sample', false)}
                className="soc-btn-secondary"
              >
                <FileCheck2 className="w-3.5 h-3.5" />
                Ingest PhishTank CSV Fixture
              </button>
            </RequirePermission>

            <RequirePermission permission={PERMISSIONS.DATASET_ADMIN} mode="disable">
              <button
                type="button"
                disabled={ingestingSource !== null}
                onClick={() => void triggerIngest('openphish_live', true)}
                className="soc-btn-primary"
              >
                <CloudDownload className="w-3.5 h-3.5" />
                Sync Live OpenPhish HTTPS Feed
              </button>
            </RequirePermission>

            <button
              type="button"
              onClick={() => {
                void loadDatasetGovernance();
                void loadSamples();
              }}
              className="soc-btn-secondary"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {banner && (
          <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-700 dark:text-emerald-300 font-mono">
            {banner}
          </div>
        )}
        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Provenance & Licensing Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="soc-card p-5 space-y-2 text-xs">
            <div className="soc-label">Corpus Telemetry</div>
            <div className="text-3xl font-black text-blue-600 dark:text-blue-400">
              {info?.total_samples.toLocaleString() ?? 0}
            </div>
            <div className="text-slate-500">
              Deduplicated phishing URLs · <strong>{info?.total_versions ?? 0}</strong> SHA-256 versions ·{' '}
              <strong>{info?.active_synced_iocs ?? 0}</strong> active enforced IOCs
            </div>
          </div>

          {(info?.sources ?? []).map((src) => (
            <div key={src.name} className="soc-card p-5 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-slate-900 dark:text-white">
                  {src.name} Feed
                </span>
                <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                  VERIFIED SOURCE
                </span>
              </div>
              <div className="font-mono text-[11px] text-slate-500 break-all">{src.feed_url}</div>
              <div className="text-[11px] text-slate-600 dark:text-slate-300">
                <strong>License:</strong> {src.license}
              </div>
              <div className="font-mono text-[10px] text-slate-500">
                Schema: {src.schema}
              </div>
            </div>
          ))}
        </div>

        {/* SHA-256 Dataset Versions Table */}
        <div className="soc-card overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Hash className="w-4 h-4 text-blue-500" />
              Immutable SHA-256 Ingestion Lineage ({versions.length})
            </h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                  <th className="p-3.5">Source / Timestamp</th>
                  <th className="p-3.5">Raw Payload SHA-256</th>
                  <th className="p-3.5">Total / New / Dupes</th>
                  <th className="p-3.5">Triggered By</th>
                  <th className="p-3.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                {versions.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                    <td className="p-3.5">
                      <div className="font-mono font-bold text-slate-900 dark:text-white">
                        {v.source}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {formatUtcDateTime(v.created_at)}
                      </div>
                    </td>
                    <td className="p-3.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      <span title={v.sha256}>{v.sha256.slice(0, 24)}…</span>
                    </td>
                    <td className="p-3.5 font-mono">
                      <span className="font-bold">{v.total_records}</span> total ·{' '}
                      <span className="text-emerald-600 dark:text-emerald-400">
                        +{v.new_records} new
                      </span>{' '}
                      · <span className="text-slate-500">{v.duplicate_records} dup</span>
                    </td>
                    <td className="p-3.5 font-mono text-[11px] text-slate-500">
                      {v.triggered_by ?? 'system'}
                    </td>
                    <td className="p-3.5">
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                        {v.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Paginated Phishing Samples Explorer */}
        <div className="soc-card overflow-hidden">
          <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">
              Deduplicated Phishing URL Samples Explorer ({samples?.total ?? 0})
            </h2>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter URL or domain..."
                  value={searchQ}
                  onChange={(e) => {
                    setSearchQ(e.target.value);
                    setSamplePage(1);
                  }}
                  className="soc-input pl-8 w-56 font-mono"
                />
              </div>
              <select
                value={sourceFilter}
                onChange={(e) => {
                  setSourceFilter(e.target.value);
                  setSamplePage(1);
                }}
                className="soc-input w-44 font-mono"
              >
                <option value="">All Sources</option>
                <option value="openphish">openphish</option>
                <option value="phishtank">phishtank</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="soc-table-head border-b border-slate-200 dark:border-slate-800">
                  <th className="p-3">Source</th>
                  <th className="p-3">Extracted Host Domain</th>
                  <th className="p-3">Normalized Phishing URL</th>
                  <th className="p-3">First Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                {(samples?.items ?? []).map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                    <td className="p-3 font-mono">
                      <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-700 dark:text-blue-300 text-[10px] font-bold">
                        {s.source}
                      </span>
                    </td>
                    <td className="p-3 font-mono font-bold text-slate-900 dark:text-white">
                      {s.domain}
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all max-w-md">
                      {s.url}
                    </td>
                    <td className="p-3 font-mono text-[10px] text-slate-500">
                      {formatUtcDateTime(s.first_seen_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-500">
              Page {samplePage} of {totalSamplePages} ({samples?.total ?? 0} URLs)
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={samplePage <= 1}
                onClick={() => setSamplePage((p) => Math.max(1, p - 1))}
                className="soc-btn-secondary px-2.5 py-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Prev
              </button>
              <button
                type="button"
                disabled={samplePage >= totalSamplePages}
                onClick={() => setSamplePage((p) => Math.min(totalSamplePages, p + 1))}
                className="soc-btn-secondary px-2.5 py-1"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </RequirePermission>
    </div>
  );
}
