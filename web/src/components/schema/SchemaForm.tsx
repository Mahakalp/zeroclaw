import { useState, useEffect } from 'react';
import { FormField } from '@/components/ui/FormField';
import { FormInput } from '@/components/ui/FormInput';
import { FormSelect } from '@/components/ui/FormSelect';
import { FormToggle } from '@/components/ui/FormToggle';
import type { Schema, SchemaField } from '@/types/api';

interface SchemaFormProps {
  schema: Schema;
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
  errors?: Record<string, string>;
  disabled?: boolean;
}

function getInitialValues(schema: Schema): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const field of schema.fields) {
    if (field.type === 'boolean') {
      values[field.name] = false;
    } else if (field.type === 'array') {
      values[field.name] = '';
    } else if (field.type === 'number') {
      values[field.name] = '';
    } else {
      values[field.name] = field.example || '';
    }
  }
  return values;
}

function parseValue(value: unknown, type: string): unknown {
  if (type === 'boolean') {
    return Boolean(value);
  }
  if (type === 'number') {
    if (value === '' || value === undefined || value === null) {
      return undefined;
    }
    const num = Number(value);
    return isNaN(num) ? undefined : num;
  }
  if (type === 'array') {
    if (!value || typeof value !== 'string') {
      return undefined;
    }
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : undefined;
    } catch {
      return value.split(',').map((s) => s.trim()).filter(Boolean);
    }
  }
  return value;
}

function validateField(field: SchemaField, value: unknown): string | undefined {
  if (field.required) {
    if (value === undefined || value === null || value === '') {
      return `${field.name} is required`;
    }
    if (Array.isArray(value) && value.length === 0) {
      return `${field.name} is required`;
    }
  }
  return undefined;
}

export function SchemaForm({
  schema,
  values: initialValues,
  onChange,
  errors = {},
  disabled = false,
}: SchemaFormProps) {
  const [values, setValues] = useState<Record<string, unknown>>(initialValues);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    setValues(initialValues);
  }, [initialValues]);

  const handleChange = (fieldName: string, fieldType: string, value: unknown) => {
    const parsedValue = parseValue(value, fieldType);
    const newValues = { ...values, [fieldName]: parsedValue };
    setValues(newValues);
    onChange(newValues);

    const field = schema.fields.find((f) => f.name === fieldName);
    if (field) {
      const fieldError = validateField(field, parsedValue);
      setFieldErrors((prev) => {
        const newErrors = { ...prev };
        if (fieldError) {
          newErrors[fieldName] = fieldError;
        } else {
          delete newErrors[fieldName];
        }
        return newErrors;
      });
    }
  };

  const allErrors = { ...fieldErrors, ...errors };

  const renderField = (field: SchemaField) => {
    const value = values[field.name];
    const error = allErrors[field.name];

    if (field.type === 'boolean') {
      return (
        <FormToggle
          checked={Boolean(value)}
          onChange={(checked) => handleChange(field.name, 'boolean', checked)}
          disabled={disabled}
        />
      );
    }

    if (field.type === 'select') {
      const options = field.options || [];
      return (
        <FormSelect
          value={String(value || '')}
          onChange={(val) => handleChange(field.name, 'select', val)}
          options={options}
          placeholder="Select an option..."
          disabled={disabled}
          error={error}
        />
      );
    }

    if (field.type === 'array') {
      const displayValue = Array.isArray(value)
        ? JSON.stringify(value)
        : String(value || '');
      return (
        <div className="space-y-1.5">
          <textarea
            value={displayValue}
            onChange={(e) => handleChange(field.name, 'array', e.target.value)}
            placeholder={field.example || '["item1", "item2"]'}
            disabled={disabled}
            rows={3}
            className={`
              w-full bg-gray-900 border text-gray-200 text-sm rounded-lg px-3 py-2.5
              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset
              transition-colors placeholder:text-gray-500 font-mono
              ${error ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 hover:border-gray-600'}
              ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
            `}
          />
          {field.hint && !error && (
            <p className="text-xs text-gray-500">{field.hint}</p>
          )}
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
      );
    }

    let inputType: 'text' | 'password' | 'number' | 'url' = 'text';
    if (field.type === 'password') {
      inputType = 'password';
    } else if (field.type === 'number') {
      inputType = 'number';
    }

    return (
      <FormInput
        value={String(value || '')}
        onChange={(val) => handleChange(field.name, field.type, val)}
        type={inputType}
        placeholder={field.example}
        disabled={disabled}
      />
    );
  };

  return (
    <div className="space-y-4">
      {schema.fields.map((field) => (
        <div key={field.name}>
          <FormField
            label={field.name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
            required={field.required}
            hint={field.type !== 'string' && field.type !== 'password' ? field.hint : undefined}
            error={allErrors[field.name]}
          >
            {renderField(field)}
          </FormField>
        </div>
      ))}
    </div>
  );
}

interface SchemaFormWrapperProps {
  schema: Schema | null;
  initialValues?: Record<string, unknown>;
  onSubmit: (values: Record<string, unknown>) => void;
  onCancel?: () => void;
  loading?: boolean;
  disabled?: boolean;
  submitLabel?: string;
  cancelLabel?: string;
}

export function SchemaFormWrapper({
  schema,
  initialValues = {},
  onSubmit,
  onCancel,
  loading = false,
  disabled = false,
  submitLabel = 'Save',
  cancelLabel = 'Cancel',
}: SchemaFormWrapperProps) {
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (schema) {
      const defaults = getInitialValues(schema);
      setValues({ ...defaults, ...initialValues });
    }
  }, [schema, initialValues]);

  if (!schema) {
    return null;
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const newErrors: Record<string, string> = {};
    for (const field of schema.fields) {
      const error = validateField(field, values[field.name]);
      if (error) {
        newErrors[field.name] = error;
      }
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    setErrors({});
    onSubmit(values);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <SchemaForm
        schema={schema}
        values={values}
        onChange={setValues}
        errors={errors}
        disabled={disabled || loading}
      />
      <div className="flex gap-3 pt-2">
        <button
          type="submit"
          disabled={disabled || loading}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg transition-colors"
        >
          {loading && (
            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                fill="none"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
          )}
          {submitLabel}
        </button>
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="text-gray-400 hover:text-white px-4 py-2 rounded-lg transition-colors"
          >
            {cancelLabel}
          </button>
        )}
      </div>
    </form>
  );
}
