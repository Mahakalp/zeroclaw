import { useState, useEffect, useCallback, useMemo } from 'react';
import { Plus, Trash2, Edit2, Loader2, Cloud } from 'lucide-react';
import {
  getProviders,
  createProvider,
  updateProvider,
  deleteProvider,
  getAllProviderSchemas,
  type Provider,
} from '@/lib/api';
import type { ProviderSchema, SchemaField } from '@/types/api';
import { SchemaFormWrapper } from '@/components/schema/SchemaForm';

interface ProviderTypeOption {
  value: string;
  label: string;
}

function getProviderTypes(): ProviderTypeOption[] {
  return [
    { value: 'openai', label: 'OpenAI' },
    { value: 'anthropic', label: 'Anthropic' },
    { value: 'google', label: 'Google (Gemini)' },
    { value: 'ollama', label: 'Ollama' },
    { value: 'openrouter', label: 'OpenRouter' },
    { value: 'groq', label: 'Groq' },
    { value: 'mistral', label: 'Mistral' },
    { value: 'deepseek', label: 'DeepSeek' },
    { value: 'xai', label: 'xAI' },
    { value: 'together-ai', label: 'Together AI' },
    { value: 'fireworks', label: 'Fireworks AI' },
    { value: 'perplexity', label: 'Perplexity' },
    { value: 'cohere', label: 'Cohere' },
    { value: 'qwen', label: 'Qwen' },
    { value: 'glm', label: 'GLM' },
    { value: 'moonshot', label: 'Moonshot' },
    { value: 'minimax', label: 'MiniMax' },
    { value: 'bedrock', label: 'Bedrock' },
    { value: 'telnyx', label: 'Telnyx' },
    { value: 'copilot', label: 'Copilot' },
    { value: 'nvidia', label: 'NVIDIA' },
    { value: 'phi4', label: 'Phi4' },
    { value: 'lmstudio', label: 'LM Studio' },
    { value: 'llamacpp', label: 'llama.cpp' },
    { value: 'sglang', label: 'SGLang' },
    { value: 'vllm', label: 'vLLM' },
    { value: 'vercel', label: 'Vercel' },
    { value: 'cloudflare', label: 'Cloudflare' },
    { value: 'venice', label: 'Venice' },
  ];
}

export default function Providers() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [providerTypes, setProviderTypes] = useState<ProviderTypeOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [providerType, setProviderType] = useState('');
  const [defaultModel, setDefaultModel] = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [isEnabled, setIsEnabled] = useState(true);
  const [formValues, setFormValues] = useState<Record<string, unknown>>({});

  const [schemaLoading, setSchemaLoading] = useState(false);
  const [currentSchema, setCurrentSchema] = useState<ProviderSchema | null>(null);
  const [schemaError, setSchemaError] = useState<string | null>(null);

  useEffect(() => {
    loadProviders();
    loadProviderTypes();
  }, []);

  const providerTypesList = useMemo(() => {
    if (providerTypes.length > 0) {
      return providerTypes;
    }
    return getProviderTypes();
  }, [providerTypes]);

  async function loadProviderTypes() {
    try {
      const data = await getAllProviderSchemas();
      if (data.providers && data.providers.length > 0) {
        const types = data.providers.map((p: ProviderSchema) => ({
          value: p.type,
          label: p.name || p.type,
        }));
        setProviderTypes(types);
      }
    } catch (e) {
      console.error('Failed to load provider types:', e);
    }
  }

  async function loadProviders() {
    try {
      const data = await getProviders();
      setProviders(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load providers');
    } finally {
      setLoading(false);
    }
  }

  const fetchSchema = useCallback(async (type: string) => {
    if (!type) {
      setCurrentSchema(null);
      return;
    }

    setSchemaLoading(true);
    setSchemaError(null);

    try {
      const schema = await getAllProviderSchemas();
      const found = schema.providers?.find((p: ProviderSchema) => p.type === type);
      if (found) {
        setCurrentSchema(found);
        setFormValues({});
      } else {
        setSchemaError(`No schema found for provider type: ${type}`);
        setCurrentSchema(null);
      }
    } catch (e) {
      setSchemaError(e instanceof Error ? e.message : 'Failed to load schema');
      setCurrentSchema(null);
    } finally {
      setSchemaLoading(false);
    }
  }, []);

  function handleProviderTypeChange(type: string) {
    setProviderType(type);
    setFormValues({});
    if (type) {
      fetchSchema(type);
    } else {
      setCurrentSchema(null);
    }
  }

  function resetForm() {
    setProviderType('');
    setCurrentSchema(null);
    setFormValues({});
    setDefaultModel('');
    setIsDefault(false);
    setIsEnabled(true);
    setShowForm(false);
    setEditingId(null);
    setSchemaError(null);
  }

  async function handleSubmit(values: Record<string, unknown>) {
    if (!providerType.trim()) return;
    setSaving(true);
    setError(null);

    try {
      const getString = (key: string): string | undefined => {
        const raw = values[key];
        if (typeof raw !== 'string') return undefined;
        const trimmed = raw.trim();
        return trimmed.length > 0 ? trimmed : undefined;
      };

      const apiKey = getString('api_key');
      const apiUrl = getString('api_url');
      const formDefaultModel = getString('default_model');
      const resolvedDefaultModel = defaultModel.trim() || formDefaultModel;

      const metadata = { ...values };
      delete metadata.api_key;
      delete metadata.api_url;
      delete metadata.default_model;

      const providerData = {
        profile_id: 'default',
        name: providerType.trim(),
        api_key: apiKey,
        api_url: apiUrl,
        default_model: resolvedDefaultModel || undefined,
        is_default: isDefault,
        is_enabled: isEnabled,
        priority: 0,
        metadata: JSON.stringify(metadata, null, 2),
      };

      if (editingId) {
        await updateProvider(editingId, providerData);
      } else {
        await createProvider(providerData);
      }

      resetForm();
      loadProviders();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save provider');
    } finally {
      setSaving(false);
    }
  }

  function startEdit(provider: Provider) {
    setProviderType(provider.name);
    setDefaultModel(provider.default_model || '');
    setIsDefault(provider.is_default);
    setIsEnabled(provider.is_enabled);
    setEditingId(provider.id);
    setShowForm(true);

    try {
      const parsed = JSON.parse(provider.metadata || '{}');
      setFormValues({
        ...parsed,
        api_key: provider.api_key || '',
        api_url: provider.api_url || '',
        default_model: provider.default_model || '',
      });
    } catch {
      setFormValues({
        api_key: provider.api_key || '',
        api_url: provider.api_url || '',
        default_model: provider.default_model || '',
      });
    }

    fetchSchema(provider.name);
  }

  async function handleDelete(id: string) {
    if (!confirm('Are you sure you want to delete this provider?')) return;
    setSaving(true);
    setError(null);
    try {
      await deleteProvider(id);
      loadProviders();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete provider');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Cloud className="h-6 w-6 text-blue-400" />
          <h1 className="text-2xl font-bold text-white">AI Providers</h1>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Provider
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300">
          {error}
        </div>
      )}

      {showForm && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h2 className="text-lg font-semibold text-white mb-4">
            {editingId ? 'Edit Provider' : 'Add New Provider'}
          </h2>

          <div className="grid gap-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Provider Type
                </label>
                <select
                  value={providerType}
                  onChange={(e) => handleProviderTypeChange(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  disabled={!!editingId}
                >
                  <option value="">Select provider...</option>
                  {providerTypesList.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Default Model
                </label>
                <input
                  type="text"
                  value={defaultModel}
                  onChange={(e) => setDefaultModel(e.target.value)}
                  placeholder="e.g., gpt-4o, claude-sonnet-4"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2 text-gray-300">
                <input
                  type="checkbox"
                  checked={isDefault}
                  onChange={(e) => setIsDefault(e.target.checked)}
                  className="rounded bg-gray-800 border-gray-700 text-blue-600 focus:ring-blue-500"
                />
                Default Provider
              </label>
              <label className="flex items-center gap-2 text-gray-300">
                <input
                  type="checkbox"
                  checked={isEnabled}
                  onChange={(e) => setIsEnabled(e.target.checked)}
                  className="rounded bg-gray-800 border-gray-700 text-blue-600 focus:ring-blue-500"
                />
                Enabled
              </label>
            </div>

            {schemaLoading && (
              <div className="flex items-center gap-2 text-gray-400 py-4">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading schema...
              </div>
            )}

            {schemaError && (
              <div className="bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">
                {schemaError}
              </div>
            )}

            {currentSchema && !schemaLoading && (
              <div className="space-y-4">
                {currentSchema.description && (
                  <div className="bg-blue-900/20 border border-blue-800 rounded-lg p-3 text-blue-300 text-sm">
                    {currentSchema.description}
                  </div>
                )}

                <div className="text-sm text-gray-400">
                  <span className="font-medium text-gray-300">Required fields: </span>
                  {currentSchema.fields
                    .filter((f: SchemaField) => f.required)
                    .map((f: SchemaField) => f.name.replace(/_/g, ' '))
                    .join(', ') || 'None'}
                </div>

                <SchemaFormWrapper
                  schema={currentSchema}
                  initialValues={formValues}
                  onSubmit={handleSubmit}
                  onCancel={resetForm}
                  loading={saving}
                  disabled={saving}
                  submitLabel={editingId ? 'Update Provider' : 'Add Provider'}
                  cancelLabel="Cancel"
                />
              </div>
            )}

            {!currentSchema && !schemaLoading && providerType && (
              <div className="text-gray-500 text-sm py-4">
                No schema available for this provider type.
              </div>
            )}
          </div>
        </div>
      )}

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h2 className="text-lg font-semibold text-white mb-4">Configured Providers</h2>
        {providers.length === 0 ? (
          <p className="text-gray-500">No providers configured. Add one to get started.</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {providers.map((provider) => (
              <div
                key={provider.id}
                className={`p-4 rounded-lg border ${
                  provider.is_enabled
                    ? 'bg-gray-800 border-gray-700'
                    : 'bg-gray-900/50 border-gray-800 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-white">
                        {providerTypesList.find((p) => p.value === provider.name)?.label ||
                          provider.name}
                      </h3>
                      {provider.is_default && (
                        <span className="px-2 py-0.5 text-xs bg-blue-700 text-blue-200 rounded">
                          Default
                        </span>
                      )}
                    </div>
                    {provider.default_model && (
                      <p className="text-sm text-gray-400 mt-1">{provider.default_model}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => startEdit(provider)}
                      className="p-1.5 hover:bg-gray-700 text-gray-400 hover:text-white rounded"
                    >
                      <Edit2 className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(provider.id)}
                      className="p-1.5 hover:bg-red-900/30 text-gray-400 hover:text-red-400 rounded"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
