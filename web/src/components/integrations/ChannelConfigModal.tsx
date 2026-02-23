import { useState, useEffect } from 'react';
import { X, Settings, Loader2 } from 'lucide-react';
import { FormInput } from '@/components/ui/FormInput';
import { getConfig, putConfig } from '@/lib/api';

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
};

function getChannelKey(name: string): string {
  return name.toLowerCase().replace(/\s+/g, '_');
}

function parseCurrentConfig(configToml: string, channelKey: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = configToml.split('\n');
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
    
    try {
      const newConfig = generateChannelConfig(channelKey, values, configToml);
      await putConfig(newConfig);
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save config');
    } finally {
      setSaving(false);
    }
  };
  
  const handleTest = async () => {
    setTesting(true);
    try {
      await getConfig();
      await new Promise(resolve => setTimeout(resolve, 500));
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
                    placeholder={field.hint}
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
