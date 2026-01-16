/**
 * Transport layer types for the SDK
 */

export interface TransportOptions {
  baseUrl: string;
  timeout?: number;
  headers?: Record<string, string>;
  debug?: boolean;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: Uint8Array | string | Record<string, unknown>;
  timeout?: number;
  retry?: {
    maxAttempts: number;
    delayMs: number;
    backoffMultiplier: number;
  };
}

export interface Response<T = unknown> {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: T;
  raw: Uint8Array;
}

export interface Transport {
  request<T = unknown>(
    method: string,
    path: string,
    options?: RequestOptions
  ): Promise<Response<T>>;

  get<T = unknown>(path: string, options?: RequestOptions): Promise<Response<T>>;

  post<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<Response<T>>;

  put<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<Response<T>>;

  delete<T = unknown>(path: string, options?: RequestOptions): Promise<Response<T>>;

  setHeader(name: string, value: string): void;

  removeHeader(name: string): void;
}

export interface HttpError extends Error {
  status: number;
  statusText: string;
  body?: unknown;
}
