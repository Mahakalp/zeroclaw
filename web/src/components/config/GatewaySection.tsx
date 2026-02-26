import { useState, useEffect } from 'react';
import { Save } from 'lucide-react';
import { FormField } from '@/components/ui/FormField';
import { FormInput } from '@/components/ui/FormInput';
import { FormToggle } from '@/components/ui/FormToggle';

interface GatewaySectionProps {
  config: string;
  onConfigChange: (newConfig: string) => void;
}

export function GatewaySection({ config, onConfigChange }: GatewaySectionProps) {
  const [port, setPort] = useState('');
  const [host, setHost] = useState('');
  const [cfAccessEnabled, setCfAccessEnabled] = useState(false);
  const [cfAccessPublicKey, setCfAccessPublicKey] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    parseConfig(config);
    setLoading(false);
  }, [config]);

  function parseConfig(toml: string) {
    const lines = toml.split('\n');
    let currentPort = '';
    let currentHost = '';
    let currentCfAccessEnabled = false;
    let currentCfAccessPublicKey = '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('[gateway]')) {
        continue;
      }
      if (trimmed.startsWith('port')) {
        const match = trimmed.match(/port\s*=\s*(\d+)/);
        if (match) currentPort = match[1] ?? '';
      } else if (trimmed.startsWith('host')) {
        const match = trimmed.match(/host\s*=\s*"([^"]*)"/);
        if (match) currentHost = match[1] ?? '';
      } else if (trimmed.startsWith('cf_access_enabled')) {
        const match = trimmed.match(/cf_access_enabled\s*=\s*(true|false)/);
        if (match) currentCfAccessEnabled = match[1] === 'true';
      } else if (trimmed.startsWith('cf_access_public_key')) {
        const match = trimmed.match(/cf_access_public_key\s*=\s*"([^"]*)"/);
        if (match) currentCfAccessPublicKey = match[1] ?? '';
      }
    }

    setPort(currentPort);
    setHost(currentHost);
    setCfAccessEnabled(currentCfAccessEnabled);
    setCfAccessPublicKey(currentCfAccessPublicKey);
  }

  function updateConfig() {
    const lines = config.split('\n');
    const newLines: string[] = [];
    let portSet = false;
    let hostSet = false;
    let cfAccessEnabledSet = false;
    let cfAccessPublicKeySet = false;
    let gatewaySectionFound = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[gateway]') {
        gatewaySectionFound = true;
        newLines.push(line);
      } else if (gatewaySectionFound && trimmed.startsWith('port')) {
        newLines.push(`port = ${port || 42617}`);
        portSet = true;
        gatewaySectionFound = false;
      } else if (gatewaySectionFound && trimmed.startsWith('host')) {
        newLines.push(`host = "${host || '127.0.0.1'}"`);
        hostSet = true;
        gatewaySectionFound = false;
      } else if (gatewaySectionFound && trimmed.startsWith('cf_access_enabled')) {
        newLines.push(`cf_access_enabled = ${cfAccessEnabled}`);
        cfAccessEnabledSet = true;
        gatewaySectionFound = false;
      } else if (gatewaySectionFound && trimmed.startsWith('cf_access_public_key')) {
        newLines.push(`cf_access_public_key = "${cfAccessPublicKey}"`);
        cfAccessPublicKeySet = true;
        gatewaySectionFound = false;
      } else {
        newLines.push(line);
      }
    }

    if (!portSet) {
      if (newLines.some(l => l.trim() === '[gateway]')) {
        const idx = newLines.findIndex(l => l.trim() === '[gateway]');
        newLines.splice(idx + 1, 0, `port = ${port || 42617}`);
      } else {
        newLines.push('[gateway]');
        newLines.push(`port = ${port || 42617}`);
      }
    }
    if (!hostSet) {
      const gatewayIdx = newLines.findIndex(l => l.trim() === '[gateway]');
      if (gatewayIdx !== -1) {
        newLines.splice(gatewayIdx + 1, 0, `host = "${host || '127.0.0.1'}"`);
      }
    }
    if (!cfAccessEnabledSet) {
      const gatewayIdx = newLines.findIndex(l => l.trim() === '[gateway]');
      if (gatewayIdx !== -1) {
        newLines.splice(gatewayIdx + 1, 0, `cf_access_enabled = ${cfAccessEnabled}`);
      }
    }
    if (!cfAccessPublicKeySet) {
      const gatewayIdx = newLines.findIndex(l => l.trim() === '[gateway]');
      if (gatewayIdx !== -1) {
        newLines.splice(gatewayIdx + 1, 0, `cf_access_public_key = "${cfAccessPublicKey}"`);
      }
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
        <div className="h-4 bg-gray-800 rounded w-1/4"></div>
        <div className="h-10 bg-gray-800 rounded"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Gateway Settings</h3>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          <Save className="h-4 w-4" />
          Save
        </button>
      </div>

      <div className="grid gap-4">
        <FormField label="Host">
          <FormInput
            value={host}
            onChange={setHost}
            placeholder="127.0.0.1"
          />
        </FormField>

        <FormField label="Port">
          <FormInput
            value={port}
            onChange={setPort}
            type="number"
            placeholder="42617"
          />
        </FormField>

        <FormField label="Cloudflare Access">
          <FormToggle
            checked={cfAccessEnabled}
            onChange={setCfAccessEnabled}
            label="Enable Cloudflare Access"
            description="Require Cloudflare Access JWT authentication"
          />
        </FormField>
      </div>
    </div>
  );
}
