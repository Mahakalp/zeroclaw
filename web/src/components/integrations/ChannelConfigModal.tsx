import { useState, useEffect } from 'react';
import { X, Settings, Loader2 } from 'lucide-react';
import { FormInput } from '@/components/ui/FormInput';
import {
  createChannel,
  createProvider,
  getChannels,
  getConfig,
  getProviderModels,
  getProviders,
  updateChannel,
  updateProvider,
} from '@/lib/api';

interface ChannelConfigModalProps {
  channel: {
    name: string;
    configured: boolean;
    enabled?: boolean;
  };
  onClose: () => void;
  onSaved: () => void;
}

interface ChannelFields {
  [key: string]: {
    label: string;
    type: 'text' | 'password' | 'url';
    required: boolean;
    hint?: string;
  }[];
}

const CHANNEL_FIELDS: ChannelFields = {
  anthropic: [
    { label: 'API Key', type: 'password', required: false, hint: 'Leave empty to use ANTHROPIC_API_KEY env var' },
    { label: 'Default Model', type: 'text', required: false, hint: 'e.g., claude-sonnet-4-20250514' },
  ],
  openai: [
    { label: 'API Key', type: 'password', required: false, hint: 'Leave empty to use OPENAI_API_KEY env var' },
    { label: 'Default Model', type: 'text', required: false, hint: 'e.g., gpt-4o' },
  ],
  google: [
    { label: 'API Key', type: 'password', required: false, hint: 'Leave empty to use GOOGLE_API_KEY env var' },
    { label: 'Default Model', type: 'text', required: false, hint: 'e.g., gemini-2.0-flash' },
  ],
  openrouter: [
    { label: 'API Key', type: 'password', required: false, hint: 'Leave empty to use OPENROUTER_API_KEY env var' },
    { label: 'Default Model', type: 'text', required: false, hint: 'e.g., openai/gpt-4o' },
  ],
  ollama: [
    { label: 'API URL', type: 'url', required: false, hint: 'e.g., http://localhost:11434' },
    { label: 'Default Model', type: 'text', required: false, hint: 'e.g., llama3' },
  ],
  telegram: [
    { label: 'Bot Token', type: 'password', required: true, hint: 'Get from @BotFather' },
    { label: 'Allowed Users', type: 'text', required: false, hint: 'Comma-separated user IDs or usernames (empty = deny all)' },
  ],
  discord: [
    { label: 'Bot Token', type: 'password', required: true, hint: 'From Discord Developer Portal' },
    { label: 'Guild ID', type: 'text', required: false, hint: 'Optional: restrict to single server' },
    { label: 'Allowed Users', type: 'text', required: false, hint: 'Comma-separated user IDs (empty = deny all)' },
  ],
  slack: [
    { label: 'Bot Token', type: 'password', required: true, hint: 'xoxb-... token from Slack App' },
    { label: 'Channel ID', type: 'text', required: false, hint: 'Optional: restrict to single channel' },
    { label: 'Allowed Users', type: 'text', required: false, hint: 'Comma-separated user IDs (empty = deny all)' },
  ],
  matrix: [
    { label: 'Homeserver', type: 'url', required: true, hint: 'e.g. https://matrix.org' },
    { label: 'Access Token', type: 'password', required: true, hint: 'Bot account access token' },
    { label: 'User ID', type: 'text', required: false, hint: 'e.g. @bot:matrix.org' },
    { label: 'Room ID', type: 'text', required: true, hint: 'e.g. !abc123:matrix.org' },
    { label: 'Allowed Users', type: 'text', required: false, hint: 'Comma-separated user IDs (empty = deny all)' },
  ],
  nostr: [
    { label: 'Private Key', type: 'password', required: true, hint: 'nsec or hex format' },
    { label: 'Relays', type: 'text', required: false, hint: 'Comma-separated relay URLs (wss://...)' },
    { label: 'Allowed Pubkeys', type: 'text', required: false, hint: 'Comma-separated npub or hex (empty = deny all)' },
  ],
  whatsapp: [
    { label: 'Access Token', type: 'password', required: false, hint: 'From Meta Business Suite (Cloud API)' },
    { label: 'Phone Number ID', type: 'text', required: false, hint: 'From Meta Business API' },
    { label: 'Verify Token', type: 'text', required: false, hint: 'Your webhook verification token' },
  ],
  dingtalk: [
    { label: 'Client ID', type: 'text', required: true, hint: 'App Key from DingTalk Open Platform' },
    { label: 'Client Secret', type: 'password', required: true, hint: 'App Secret from DingTalk Open Platform' },
    { label: 'Allowed Users', type: 'text', required: false, hint: 'Comma-separated user IDs (empty = deny all, * = allow all)' },
  ],
  signal: [
    { label: 'Phone Number', type: 'text', required: true, hint: 'Your Signal number (e.g., +1234567890)' },
    { label: 'Storage Path', type: 'text', required: false, hint: 'Path to Signal DB (default: ~/.local/share/signal-cli)' },
  ],
  webhook: [
    { label: 'URL', type: 'url', required: true, hint: 'Incoming webhook URL' },
    { label: 'Secret', type: 'password', required: false, hint: 'Webhook secret for verification' },
  ],
  email: [
    { label: 'SMTP Host', type: 'text', required: true, hint: 'e.g., smtp.gmail.com' },
    { label: 'SMTP Port', type: 'text', required: true, hint: 'e.g., 587' },
    { label: 'Username', type: 'text', required: true, hint: 'SMTP username' },
    { label: 'Password', type: 'password', required: true, hint: 'SMTP password or app password' },
    { label: 'From Address', type: 'text', required: true, hint: 'e.g., bot@example.com' },
  ],
  imessage: [
    { label: 'Apple ID', type: 'text', required: false, hint: 'Apple ID for iCloud (if usingicloud)' },
    { label: 'Password', type: 'password', required: false, hint: 'App-specific password' },
  ],
  qq: [
    { label: 'Bot ID', type: 'text', required: true, hint: 'QQ bot ID' },
    { label: 'Token', type: 'password', required: true, hint: 'QQ bot token' },
  ],
  feishu: [
    { label: 'App ID', type: 'text', required: true, hint: 'Feishu/Lark app ID' },
    { label: 'App Secret', type: 'password', required: true, hint: 'Feishu/Lark app secret' },
  ],
  nextcloud_talk: [
    { label: 'URL', type: 'url', required: true, hint: 'Nextcloud instance URL' },
    { label: 'Bot User', type: 'text', required: true, hint: 'Bot username' },
    { label: 'Password', type: 'password', required: true, hint: 'Bot password' },
  ],
  linq: [
    { label: 'API Key', type: 'password', required: true, hint: 'LINQ API key' },
  ],
  mattermost: [
    { label: 'Server URL', type: 'url', required: true, hint: 'Mattermost server URL' },
    { label: 'Bot Token', type: 'password', required: true, hint: 'Mattermost bot token' },
    { label: 'Team', type: 'text', required: false, hint: 'Mattermost team name' },
  ],
  irc: [
    { label: 'Server', type: 'text', required: true, hint: 'IRC server (e.g., irc.libera.chat)' },
    { label: 'Port', type: 'text', required: false, hint: 'Port (default: 6697)' },
    { label: 'Nickname', type: 'text', required: true, hint: 'Bot nickname' },
    { label: 'Channel', type: 'text', required: true, hint: 'Channel to join (e.g., #zeroclaw)' },
    { label: 'Password', type: 'password', required: false, hint: 'Server or channel password' },
  ],
  clawdtalk: [
    { label: 'Server URL', type: 'url', required: true, hint: 'ClawdTalk server URL' },
    { label: 'API Key', type: 'password', required: true, hint: 'ClawdTalk API key' },
  ],
};

const PROVIDER_KEYS = ['anthropic', 'openai', 'google', 'openrouter', 'ollama', 'groq', 'deepseek', 'mistral', 'xai', 'together', 'fireworks', 'perplexity', 'cohere', 'qwen', 'glm', 'moonshot', 'minimax'];

function getChannelKey(name: string): string {
  return name.toLowerCase().replace(/\s+/g, '_');
}

function isProviderKey(key: string): boolean {
  return PROVIDER_KEYS.includes(key);
}

function modelBelongsToProvider(channelKey: string, model: string): boolean {
  const m = model.toLowerCase();
  switch (channelKey) {
    case 'google':
      return m.startsWith('google/') || m.startsWith('gemini');
    case 'anthropic':
      return m.startsWith('anthropic/') || m.startsWith('claude');
    case 'openai':
      return m.startsWith('openai/') || m.startsWith('gpt-') || m.startsWith('o1');
    case 'openrouter':
      return m.includes('/');
    case 'deepseek':
      return m.startsWith('deepseek/');
    case 'xai':
      return m.startsWith('x-ai/') || m.startsWith('grok');
    default:
      return true;
  }
}

function parseCurrentConfig(configToml: string, channelKey: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = configToml.split('\n');
  const MASKED = '***MASKED***';
  
  if (isProviderKey(channelKey)) {
    let parsedDefaultProvider = '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('[') || trimmed.startsWith('#')) continue;
      
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        let value = trimmed.slice(eqIdx + 1).trim();
        
        if (value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        
        if (value === MASKED) {
          value = '';
        }

        if (key === 'default_provider') {
          parsedDefaultProvider = value;
        }

        if (key === 'api_key' || key === 'api_url' || key === 'default_model') {
          result[key] = value;
        }
      }
    }

    if (
      result.default_model &&
      parsedDefaultProvider !== channelKey &&
      !modelBelongsToProvider(channelKey, result.default_model)
    ) {
      result.default_model = '';
    }

    return result;
  }
  
  let inChannel = false;
  let currentField = '';

  for (const line of lines) {
    const trimmed = line.trim();
    
    if (trimmed.startsWith('[channels_config.')) {
      const section = trimmed.slice(19, -1);
      inChannel = section === channelKey;
      continue;
    }
    
    if (inChannel && trimmed.startsWith('[')) {
      break;
    }
    
    if (inChannel && trimmed && !trimmed.startsWith('#')) {
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        let value = trimmed.slice(eqIdx + 1).trim();
        
        if (value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        
        if (value.startsWith('[') && value.endsWith(']')) {
          value = value.slice(1, -1).split(',').map(v => v.trim().replace(/^"|"$/g, '')).join(', ');
        }

        if (value === MASKED) {
          value = '';
        }
        
        currentField = key;
        result[key] = value;
      } else if (currentField && trimmed.startsWith('-')) {
        const value = trimmed.slice(1).trim().replace(/^"|"$/g, '');
        result[currentField] = result[currentField] ? `${result[currentField]}, ${value}` : value;
      }
    }
  }
  
  return result;
}

function generateChannelConfig(channelKey: string, values: Record<string, string>, existingConfig: string): string {
  if (isProviderKey(channelKey)) {
    const updates = Object.entries(values)
      .filter(([, value]) => Boolean(value))
      .map(([key, value]) => [key, key === 'default_provider' ? channelKey : value] as const);

    if (updates.length === 0) {
      return existingConfig;
    }

    const lines = existingConfig.split('\n');
    let inSection = false;
    const seen = new Set<string>();

    const updated = lines.map((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('[')) {
        inSection = true;
        return line;
      }

      if (inSection || !trimmed.includes('=')) {
        return line;
      }

      const rawKey = trimmed.split('=', 1)[0] ?? '';
      const key = rawKey.trim();
      const match = updates.find(([k]) => k === key);
      if (!match) {
        return line;
      }

      seen.add(key);
      return `${key} = "${match[1]}"`;
    });

    const missing = updates.filter(([key]) => !seen.has(key));
    if (missing.length === 0) {
      return updated.join('\n');
    }

    const firstSectionIndex = updated.findIndex((line) => line.trim().startsWith('['));
    const insertLines = missing.map(([key, value]) => `${key} = "${value}"`);

    if (firstSectionIndex === -1) {
      const base = updated.join('\n').replace(/\n+$/, '');
      return `${base}\n${insertLines.join('\n')}\n`;
    }

    const before = updated.slice(0, firstSectionIndex);
    const after = updated.slice(firstSectionIndex);
    return [...before, ...insertLines, ...after].join('\n');
  }
  
  const channelSection = `[channels_config.${channelKey}]\n`;
  let newConfig = existingConfig;
  
  const existingSectionStart = existingConfig.indexOf(`[channels_config.${channelKey}]`);
  const existingSectionEnd = existingSectionStart >= 0 
    ? existingConfig.indexOf('\n[channels_config.', existingSectionStart + 1)
    : -1;
  
  if (existingSectionStart >= 0) {
    const before = existingConfig.slice(0, existingSectionStart);
    const after = existingSectionEnd >= 0 ? existingConfig.slice(existingSectionEnd) : '';
    newConfig = before + channelSection + after;
  } else {
    const insertPoint = existingConfig.lastIndexOf('\n[channels_config.');
    if (insertPoint >= 0) {
      const before = existingConfig.slice(0, insertPoint);
      const after = existingConfig.slice(insertPoint);
      newConfig = before + '\n' + channelSection + after;
    } else {
      newConfig = existingConfig + '\n' + channelSection;
    }
  }
  
  for (const [key, value] of Object.entries(values)) {
    if (value) {
      let tomlValue: string;
      if (value.includes(',') || key === 'relays') {
        const items = value.split(',').map(v => v.trim()).filter(Boolean);
        tomlValue = items.map(v => `"${v}"`).join(', ');
        newConfig = newConfig.replace(
          `[channels_config.${channelKey}]`,
          `[channels_config.${channelKey}]\n${key} = [${tomlValue}]`
        );
      } else {
        tomlValue = value;
        newConfig = newConfig.replace(
          `[channels_config.${channelKey}]`,
          `[channels_config.${channelKey}]\n${key} = "${tomlValue}"`
        );
      }
    }
  }
  
  return newConfig;
}

export function ChannelConfigModal({ channel, onClose, onSaved }: ChannelConfigModalProps) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [configToml, setConfigToml] = useState<string>('');
  const [values, setValues] = useState<Record<string, string>>({});
  
  const channelKey = getChannelKey(channel.name);
  const fields = CHANNEL_FIELDS[channelKey] || [];
  
  useEffect(() => {
    getConfig()
      .then((config) => {
        setConfigToml(config);
        const parsed = parseCurrentConfig(config, channelKey);
        setValues(parsed);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [channelKey]);
  
  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setMessage(null);
    
    try {
      const allowedFieldKeys = new Set(fields.map((f) => fieldNameToKey(f.label)));
      const sanitizedValues: Record<string, string> = Object.fromEntries(
        Object.entries(values).filter(([k, v]) => allowedFieldKeys.has(k) && v !== '***MASKED***')
      );

      if (isProviderKey(channelKey)) {
        sanitizedValues.default_provider = channelKey;
        
        // Save provider to database
        const providers = await getProviders();
        const existing = providers.find((p) => p.name === channelKey);
        const providerPayload = {
          profile_id: existing?.profile_id || 'default',
          name: channelKey,
          api_key: sanitizedValues.api_key || undefined,
          api_url: sanitizedValues.api_url || undefined,
          default_model: sanitizedValues.default_model || undefined,
          is_enabled: true,
          is_default: true,
          priority: existing?.priority ?? 0,
          metadata: existing?.metadata || '{}',
        };

        if (existing) {
          await updateProvider(existing.id, providerPayload);
        } else {
          await createProvider(providerPayload);
        }
      } else {
        // Save channel to database instead of config.toml
        const newConfig = generateChannelConfig(channelKey, sanitizedValues, configToml);
        
        // Get existing channels from database
        const channels = await getChannels();
        const existingChannel = channels.find((c) => c.channel_type === channelKey);
        
        const channelPayload = {
          profile_id: 'default',
          channel_type: channelKey,
          config: newConfig,
          is_enabled: true,
        };

        if (existingChannel) {
          await updateChannel(existingChannel.id, channelPayload);
        } else {
          await createChannel(channelPayload);
        }
      }

      onSaved();
      onClose();
    } catch (err) {
      console.error('ChannelConfigModal: save failed', {
        channelKey,
        valueKeys: Object.keys(values),
        error: err,
      });
      setError(err instanceof Error ? err.message : 'Failed to save config');
    } finally {
      setSaving(false);
    }
  };
  
  const handleTest = async () => {
    setTesting(true);
    setError(null);
    setMessage(null);
    try {
      if (isProviderKey(channelKey)) {
        const models = await getProviderModels(channelKey, {
          apiKey: values.api_key,
          apiUrl: values.api_url,
        });
        setMessage(
          models.length > 0
            ? `Connection looks good. Found ${models.length} model(s).`
            : 'Connection succeeded, but no models were returned for this provider.'
        );
      } else {
        await getConfig();
        setMessage('Configuration endpoint is reachable.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection test failed');
    } finally {
      setTesting(false);
    }
  };
  
  const handleChange = (field: string, value: string) => {
    setValues(prev => ({ ...prev, [field]: value }));
  };
  
  const fieldNameToKey = (label: string): string => {
    return label.toLowerCase().replace(/\s+/g, '_');
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
          <Loader2 className="h-6 w-6 animate-spin text-blue-500" />
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Settings className="h-5 w-5 text-blue-400" />
            <h3 className="text-lg font-semibold text-white">
              Configure {channel.name}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-lg bg-red-900/30 border border-red-700 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {message && !error && (
          <div className="mb-4 rounded-lg bg-green-900/30 border border-green-700 p-3 text-sm text-green-300">
            {message}
          </div>
        )}

        {fields.length === 0 ? (
          <div className="text-gray-400 text-sm py-4">
            No configuration options available for {channel.name}.
          </div>
        ) : (
          <div className="space-y-4">
            {fields.map((field) => {
              const fieldKey = fieldNameToKey(field.label);
              return (
                <div key={fieldKey}>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    {field.label}
                    {field.required && <span className="text-red-400 ml-1">*</span>}
                  </label>
                  <FormInput
                    value={values[fieldKey] || ''}
                    onChange={(v) => handleChange(fieldKey, v)}
                    type={field.type}
                    placeholder={field.type === 'password' ? '' : field.hint}
                    hint={field.hint}
                  />
                </div>
              );
            })}
          </div>
        )}

        <div className="flex gap-3 mt-6 pt-4 border-t border-gray-700">
          <button
            onClick={handleTest}
            disabled={testing}
            className="flex-1 flex items-center justify-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium px-4 py-2.5 rounded-lg transition-colors disabled:opacity-50"
          >
            {testing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Testing...
              </>
            ) : (
              'Test Connection'
            )}
          </button>
          <button
            onClick={handleSave}
            disabled={saving || fields.length === 0}
            className="flex-1 flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors disabled:opacity-50"
          >
            {saving ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              'Save'
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
