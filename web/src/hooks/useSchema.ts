import { useState, useEffect, useCallback, useRef } from 'react';
import {
  getChannelSchema,
  getAllChannelSchemas,
  getProviderSchema,
  getAllProviderSchemas,
} from '../lib/api';
import type { ChannelSchema, ProviderSchema } from '../types/api';

interface UseSchemaResult<T> {
  schema: T | null;
  error: Error | null;
  loading: boolean;
  refetch: () => void;
}

interface UseSchemaListResult<T> {
  schemas: T[];
  error: Error | null;
  loading: boolean;
  refetch: () => void;
}

function useSchemaFetch<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
): UseSchemaResult<T> {
  const [schema, setSchema] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const mountedRef = useRef(true);
  const triggerRef = useRef(0);

  const refetch = useCallback(() => {
    triggerRef.current += 1;
    setLoading(true);
    setError(null);

    fetcher()
      .then((result) => {
        if (mountedRef.current) {
          setSchema(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (mountedRef.current) {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      })
      .finally(() => {
        if (mountedRef.current) {
          setLoading(false);
        }
      });
  }, [fetcher, ...deps]);

  useEffect(() => {
    mountedRef.current = true;
    refetch();
    return () => {
      mountedRef.current = false;
    };
  }, [refetch]);

  return { schema, error, loading, refetch };
}

function useSchemaListFetch<T>(
  fetcher: () => Promise<{ channels?: T[]; providers?: T[] }>,
  key: 'channels' | 'providers',
  deps: unknown[] = [],
): UseSchemaListResult<T> {
  const [schemas, setSchemas] = useState<T[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const mountedRef = useRef(true);
  const triggerRef = useRef(0);

  const refetch = useCallback(() => {
    triggerRef.current += 1;
    setLoading(true);
    setError(null);

    fetcher()
      .then((result) => {
        if (mountedRef.current) {
          const schemaList = result[key] || [];
          setSchemas(schemaList);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (mountedRef.current) {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      })
      .finally(() => {
        if (mountedRef.current) {
          setLoading(false);
        }
      });
  }, [fetcher, key, ...deps]);

  useEffect(() => {
    mountedRef.current = true;
    refetch();
    return () => {
      mountedRef.current = false;
    };
  }, [refetch]);

  return { schemas, error, loading, refetch };
}

export function useChannelSchema(type: string): UseSchemaResult<ChannelSchema> {
  const fetcher = useCallback(() => getChannelSchema(type), [type]);
  return useSchemaFetch(fetcher, [type]);
}

export function useAllChannelSchemas(): UseSchemaListResult<ChannelSchema> {
  return useSchemaListFetch(getAllChannelSchemas, 'channels');
}

export function useProviderSchema(type: string): UseSchemaResult<ProviderSchema> {
  const fetcher = useCallback(() => getProviderSchema(type), [type]);
  return useSchemaFetch(fetcher, [type]);
}

export function useAllProviderSchemas(): UseSchemaListResult<ProviderSchema> {
  return useSchemaListFetch(getAllProviderSchemas, 'providers');
}
