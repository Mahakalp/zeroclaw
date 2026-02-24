import { useState, useEffect } from 'react';
import { Eye, EyeOff, Save, AlertCircle } from 'lucide-react';
import { FormField } from '@/components/ui/FormField';
import { FormInput } from '@/components/ui/FormInput';
import { FormSelect } from '@/components/ui/FormSelect';

const PROVIDERS = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'google', label: 'Google Gemini' },
  { value: 'ollama', label: 'Ollama' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'groq', label: 'Groq' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'mistral', label: 'Mistral' },
  { value: 'xai', label: 'xAI (Grok)' },
  { value: 'together', label: 'Together AI' },
  { value: 'fireworks', label: 'Fireworks AI' },
  { value: 'perplexity', label: 'Perplexity' },
  { value: 'cohere', label: 'Cohere' },
  { value: 'qwen', label: 'Qwen' },
  { value: 'glm', label: 'GLM' },
  { value: 'moonshot', label: 'Moonshot (Kimi)' },
  { value: 'minimax', label: 'MiniMax' },
  { value: 'bedrock', label: 'AWS Bedrock' },
  { value: 'telnyx', label: 'Telnyx' },
  { value: 'copilot', label: 'GitHub Copilot' },
  { value: 'nvidia', label: 'NVIDIA NIM' },
  { value: 'phi4', label: 'Phi-4 (Azure)' },
  { value: 'lmstudio', label: 'LM Studio' },
  { value: 'llamacpp', label: 'llama.cpp' },
  { value: 'sglang', label: 'SGLang' },
  { value: 'vllm', label: 'vLLM' },
  { value: 'vercel', label: 'Vercel AI' },
  { value: 'cloudflare', label: 'Cloudflare AI' },
];

interface ProviderSectionProps {
  config: string;
  onConfigChange: (newConfig: string) => void;
}

export function ProviderSection({ config, onConfigChange }: ProviderSectionProps) {
  const [provider, setProvider] = useState('');
  const [model, setModel] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    parseConfig(config);
    setLoading(false);
  }, [config]);

  function parseConfig(toml: string) {
    const lines = toml.split('\n');
    let currentProvider = '';
    let currentModel = '';
    let currentApiKey = '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('default_provider')) {
        const match = trimmed.match(/default_provider\s*=\s*"([^"]*)"/);
        if (match) currentProvider = match[1] ?? '';
      } else if (trimmed.startsWith('default_model')) {
        const match = trimmed.match(/default_model\s*=\s*"([^"]*)"/);
        if (match) currentModel = match[1] ?? '';
      } else if (trimmed.startsWith('api_key')) {
        const match = trimmed.match(/api_key\s*=\s*"([^"]*)"/);
        if (match) currentApiKey = match[1] ?? '';
      }
    }

    setProvider(currentProvider);
    setModel(currentModel);
    setApiKey(currentApiKey);
  }

  function updateConfig() {
    const lines = config.split('\n');
    const newLines: string[] = [];
    let providerSet = false;
    let modelSet = false;
    let apiKeySet = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('default_provider')) {
        newLines.push(`default_provider = "${provider}"`);
        providerSet = true;
      } else if (trimmed.startsWith('default_model')) {
        newLines.push(`default_model = "${model}"`);
        modelSet = true;
      } else if (trimmed.startsWith('api_key')) {
        if (apiKey) {
          newLines.push(`api_key = "${apiKey}"`);
        }
        apiKeySet = true;
      } else {
        newLines.push(line);
      }
    }

    if (!providerSet && provider) {
      newLines.push(`default_provider = "${provider}"`);
    }
    if (!modelSet && model) {
      newLines.push(`default_model = "${model}"`);
    }
    if (!apiKeySet && apiKey) {
      newLines.push(`api_key = "${apiKey}"`);
    }

    onConfigChange(newLines.join('\n'));
  }

  function handleSave() {
    updateConfig();
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-4">
        <div className="h-4 bg-gray-800 rounded w-1/4"></div>
        <div className="h-10 bg-gray-800 rounded"></div>
        <div className="h-4 bg-gray-800 rounded w-1/4"></div>
        <div className="h-10 bg-gray-800 rounded"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Provider Settings</h3>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          <Save className="h-4 w-4" />
          Save
        </button>
      </div>

      <div className="grid gap-4">
        <FormField label="Provider">
          <FormSelect
            value={provider}
            onChange={setProvider}
            options={PROVIDERS}
            placeholder="Select a provider"
          />
        </FormField>

        <FormField label="Model" hint="Enter model name (e.g., gpt-4o, claude-sonnet-4.6, MiniMax-M2.5)">
          <FormInput
            value={model}
            onChange={setModel}
            placeholder="e.g., gpt-4o, claude-sonnet-4.6, MiniMax-M2.5"
          />
        </FormField>

        <FormField label="API Key" hint="Leave empty to use environment variable">
          <div className="relative">
            <FormInput
              value={apiKey}
              onChange={setApiKey}
              type={showApiKey ? 'text' : 'password'}
              placeholder="sk-..."
            />
            <button
              type="button"
              onClick={() => setShowApiKey(!showApiKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300"
            >
              {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </FormField>
      </div>

      {!provider && (
        <div className="flex items-center gap-2 text-amber-400 text-sm">
          <AlertCircle className="h-4 w-4" />
          <span>No provider configured. Set provider, model, and optionally API key.</span>
        </div>
      )}
    </div>
  );
}
