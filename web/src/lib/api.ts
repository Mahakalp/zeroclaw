import type {
  StatusResponse,
  ToolSpec,
  CronJob,
  Integration,
  DiagResult,
  MemoryEntry,
  CostSummary,
  CliTool,
  HealthSnapshot,
  ChannelSchema,
  ProviderSchema,
} from '../types/api';
import { clearToken, getToken } from './auth';

// ---------------------------------------------------------------------------
// Base fetch wrapper
// ---------------------------------------------------------------------------

export class UnauthorizedError extends Error {
  constructor() {
    super('Unauthorized');
    this.name = 'UnauthorizedError';
  }
}

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers);

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (
    options.body &&
    typeof options.body === 'string' &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(path, { ...options, headers });

  if (response.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('zeroclaw-unauthorized'));
    throw new UnauthorizedError();
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`API ${response.status}: ${text || response.statusText}`);
  }

  // Some endpoints may return 204 No Content
  if (response.status === 204) {
    return undefined as unknown as T;
  }

  return response.json() as Promise<T>;
}

function unwrapField<T>(value: T | Record<string, T>, key: string): T {
  if (value !== null && typeof value === 'object' && !Array.isArray(value) && key in value) {
    const unwrapped = (value as Record<string, T | undefined>)[key];
    if (unwrapped !== undefined) {
      return unwrapped;
    }
  }
  return value as T;
}

// ---------------------------------------------------------------------------
// Status / Health
// ---------------------------------------------------------------------------

export function getStatus(): Promise<StatusResponse> {
  return apiFetch<StatusResponse>('/api/status');
}

export function getHealth(): Promise<HealthSnapshot> {
  return apiFetch<HealthSnapshot | { health: HealthSnapshot }>('/api/health').then((data) =>
    unwrapField(data, 'health'),
  );
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export function getConfig(): Promise<string> {
  return apiFetch<string | { format?: string; content: string }>('/api/config').then((data) =>
    typeof data === 'string' ? data : data.content,
  );
}

export function putConfig(toml: string): Promise<void> {
  return apiFetch<void>('/api/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/toml' },
    body: toml,
  });
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export function getTools(): Promise<ToolSpec[]> {
  return apiFetch<ToolSpec[] | { tools: ToolSpec[] }>('/api/tools').then((data) =>
    unwrapField(data, 'tools'),
  );
}

export function toggleTool(name: string, enabled: boolean): Promise<void> {
  return apiFetch<{ status: string }>(`/api/tools/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  }).then(() => undefined);
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

export function getCronJobs(): Promise<CronJob[]> {
  return apiFetch<CronJob[] | { jobs: CronJob[] }>('/api/cron').then((data) =>
    unwrapField(data, 'jobs'),
  );
}

export function addCronJob(body: {
  name?: string;
  command: string;
  schedule: string;
  enabled?: boolean;
}): Promise<CronJob> {
  return apiFetch<CronJob | { status: string; job: CronJob }>('/api/cron', {
    method: 'POST',
    body: JSON.stringify(body),
  }).then((data) => (typeof (data as { job?: CronJob }).job === 'object' ? (data as { job: CronJob }).job : (data as CronJob)));
}

export function deleteCronJob(id: string): Promise<void> {
  return apiFetch<void>(`/api/cron/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Integrations
// ---------------------------------------------------------------------------

export function getIntegrations(): Promise<Integration[]> {
  return apiFetch<Integration[] | { integrations: Integration[] }>('/api/integrations').then(
    (data) => unwrapField(data, 'integrations'),
  );
}

export function toggleChannel(name: string, enabled: boolean): Promise<void> {
  return apiFetch<{ status: string }>(`/api/channels/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  }).then(() => undefined);
}

// ---------------------------------------------------------------------------
// Doctor / Diagnostics
// ---------------------------------------------------------------------------

export function runDoctor(): Promise<DiagResult[]> {
  return apiFetch<DiagResult[] | { results: DiagResult[]; summary?: unknown }>('/api/doctor', {
    method: 'POST',
  }).then(
    (data) => (Array.isArray(data) ? data : data.results),
  );
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

export function getMemory(
  query?: string,
  category?: string,
): Promise<MemoryEntry[]> {
  const params = new URLSearchParams();
  if (query) params.set('query', query);
  if (category) params.set('category', category);
  const qs = params.toString();
  return apiFetch<MemoryEntry[] | { entries: MemoryEntry[] }>(`/api/memory${qs ? `?${qs}` : ''}`).then(
    (data) => unwrapField(data, 'entries'),
  );
}

export function storeMemory(
  key: string,
  content: string,
  category?: string,
): Promise<void> {
  return apiFetch<unknown>('/api/memory', {
    method: 'POST',
    body: JSON.stringify({ key, content, category }),
  }).then(() => undefined);
}

export function deleteMemory(key: string): Promise<void> {
  return apiFetch<void>(`/api/memory/${encodeURIComponent(key)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

export function getCost(): Promise<CostSummary> {
  return apiFetch<CostSummary | { cost: CostSummary }>('/api/cost').then((data) =>
    unwrapField(data, 'cost'),
  );
}

// ---------------------------------------------------------------------------
// CLI Tools
// ---------------------------------------------------------------------------

export function getCliTools(): Promise<CliTool[]> {
  return apiFetch<CliTool[] | { cli_tools: CliTool[] }>('/api/cli-tools').then((data) =>
    unwrapField(data, 'cli_tools'),
  );
}

// ---------------------------------------------------------------------------
// Profiles (Database-backed config)
// ---------------------------------------------------------------------------

export interface Profile {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export function getProfiles(): Promise<Profile[]> {
  return apiFetch<Profile[]>('/api/profiles');
}

export function createProfile(name: string, description?: string): Promise<Profile> {
  return apiFetch<Profile>('/api/profiles', {
    method: 'POST',
    body: JSON.stringify({ name, description }),
  });
}

export function activateProfile(id: string): Promise<void> {
  return apiFetch<void>(`/api/profiles/${id}/activate`, {
    method: 'POST',
  });
}

export function deleteProfile(id: string): Promise<void> {
  return apiFetch<void>(`/api/profiles/${id}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Providers (Database-backed config)
// ---------------------------------------------------------------------------

export interface Provider {
  id: string;
  profile_id: string;
  name: string;
  api_key?: string;
  api_url?: string;
  default_model?: string;
  is_enabled: boolean;
  is_default: boolean;
  priority: number;
  metadata?: string;
  created_at: string;
  updated_at: string;
}

export function getProviders(profileId?: string): Promise<Provider[]> {
  const params = profileId ? `?profile_id=${profileId}` : '';
  return apiFetch<Provider[]>(`/api/providers${params}`);
}

export function getProviderModels(provider: string): Promise<string[]> {
  return apiFetch<{ models: string[] }>(`/api/providers/${encodeURIComponent(provider)}/models`).then(
    (data) => data.models ?? [],
  );
}

export function createProvider(provider: Partial<Provider> & { profile_id: string; name: string }): Promise<Provider> {
  return apiFetch<Provider>('/api/providers', {
    method: 'POST',
    body: JSON.stringify(provider),
  });
}

export function updateProvider(id: string, provider: Partial<Provider>): Promise<Provider> {
  return apiFetch<Provider>(`/api/providers/${id}`, {
    method: 'PUT',
    body: JSON.stringify(provider),
  });
}

export function deleteProvider(id: string): Promise<void> {
  return apiFetch<void>(`/api/providers/${id}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Channels (Database-backed config)
// ---------------------------------------------------------------------------

export interface Channel {
  id: string;
  profile_id: string;
  channel_type: string;
  config: string;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export function getChannels(profileId?: string): Promise<Channel[]> {
  const params = profileId ? `?profile_id=${profileId}` : '';
  return apiFetch<Channel[]>(`/api/channels${params}`);
}

export function createChannel(channel: Partial<Channel> & { profile_id: string; channel_type: string; config: string }): Promise<Channel> {
  return apiFetch<Channel>('/api/channels', {
    method: 'POST',
    body: JSON.stringify(channel),
  });
}

export function updateChannel(id: string, channel: Partial<Channel>): Promise<Channel> {
  return apiFetch<Channel>(`/api/channels/${id}`, {
    method: 'PUT',
    body: JSON.stringify(channel),
  });
}

export function deleteChannel(id: string): Promise<void> {
  return apiFetch<void>(`/api/channels/${id}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Schema API
// ---------------------------------------------------------------------------

export function getChannelSchema(type: string): Promise<ChannelSchema> {
  return apiFetch<ChannelSchema>(`/api/schema/channels/${encodeURIComponent(type)}`);
}

export function getAllChannelSchemas(): Promise<{ channels: ChannelSchema[] }> {
  return apiFetch<{ channels: ChannelSchema[] }>('/api/schema/channels');
}

export function getProviderSchema(type: string): Promise<ProviderSchema> {
  return apiFetch<ProviderSchema>(`/api/schema/providers/${encodeURIComponent(type)}`);
}

export function getAllProviderSchemas(): Promise<{ providers: ProviderSchema[] }> {
  return apiFetch<{ providers: ProviderSchema[] }>('/api/schema/providers');
}
