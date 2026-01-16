/**
 * HTTP transport implementation for ZHTP/Web4 API
 */

import { Transport, TransportOptions, RequestOptions, Response } from './types.js';

export class HttpError extends Error {
  status: number = 0;
  statusText: string = '';
  body?: unknown;

  constructor(message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

export class HttpTransport implements Transport {
  private baseUrl: string;
  private timeout: number;
  private headers: Map<string, string>;
  private debug: boolean;

  constructor(options: TransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.timeout = options.timeout ?? 30000;
    this.debug = options.debug ?? false;
    this.headers = new Map(Object.entries(options.headers ?? {}));

    // Set default headers
    if (!this.headers.has('Content-Type')) {
      this.headers.set('Content-Type', 'application/json');
    }
  }

  async request<T = unknown>(
    method: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<Response<T>> {
    const url = `${this.baseUrl}${path}`;
    const headers = new Headers(this.buildHeaders(options.headers));
    const timeout = options.timeout ?? this.timeout;

    let body: string | Uint8Array | undefined;
    if (options.body) {
      if (typeof options.body === 'string') {
        body = options.body;
      } else if (options.body instanceof Uint8Array) {
        body = options.body;
      } else {
        body = JSON.stringify(options.body);
      }
    }

    const retryConfig = options.retry ?? {
      maxAttempts: 3,
      delayMs: 100,
      backoffMultiplier: 2,
    };

    let lastError: Error | undefined;
    for (let attempt = 0; attempt < retryConfig.maxAttempts; attempt++) {
      try {
        if (this.debug) {
          console.debug(`[HTTP] ${method} ${url}`, { attempt, body });
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
          const response = await fetch(url, {
            method,
            headers,
            body,
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          const raw = new Uint8Array(await response.arrayBuffer());
          let parsed: T;

          const contentType = response.headers.get('content-type');
          if (contentType?.includes('application/json')) {
            const text = new TextDecoder().decode(raw);
            parsed = JSON.parse(text) as T;
          } else {
            parsed = raw as T;
          }

          if (!response.ok) {
            const error = new HttpError(
              `HTTP ${response.status}: ${response.statusText}`
            ) as HttpError;
            error.status = response.status;
            error.statusText = response.statusText;
            error.body = parsed;

            // Don't retry 4xx errors
            if (response.status >= 400 && response.status < 500) {
              throw error;
            }

            lastError = error;
            if (attempt < retryConfig.maxAttempts - 1) {
              const delay = retryConfig.delayMs * Math.pow(retryConfig.backoffMultiplier, attempt);
              await this.sleep(delay);
              continue;
            }
            throw error;
          }

          const responseHeaders: Record<string, string> = {};
          response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
          });

          return {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
            body: parsed,
            raw,
          };
        } finally {
          clearTimeout(timeoutId);
        }
      } catch (error) {
        if (error instanceof HttpError) {
          lastError = error;
          // Don't retry client errors
          if (error.status >= 400 && error.status < 500) {
            throw error;
          }
        } else if (error instanceof Error) {
          lastError = error;
        } else {
          lastError = new Error('Unknown HTTP error');
        }

        // Retry on network errors
        if (attempt < retryConfig.maxAttempts - 1) {
          const delay = retryConfig.delayMs * Math.pow(retryConfig.backoffMultiplier, attempt);
          await this.sleep(delay);
          continue;
        }
      }
    }

    throw lastError ?? new Error('Unknown HTTP error');
  }

  async get<T = unknown>(path: string, options?: RequestOptions): Promise<Response<T>> {
    const opts: RequestOptions = options || {};
    return this.request<T>('GET', path, { ...opts, method: 'GET' });
  }

  async post<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<Response<T>> {
    const opts: RequestOptions = options || {};
    const requestOpts: RequestOptions = {
      ...opts,
      body: body as string | Uint8Array | Record<string, unknown> | undefined,
      method: 'POST',
    };
    return this.request<T>('POST', path, requestOpts);
  }

  async put<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<Response<T>> {
    const opts: RequestOptions = options || {};
    const requestOpts: RequestOptions = {
      ...opts,
      body: body as string | Uint8Array | Record<string, unknown> | undefined,
      method: 'PUT',
    };
    return this.request<T>('PUT', path, requestOpts);
  }

  async delete<T = unknown>(path: string, options?: RequestOptions): Promise<Response<T>> {
    const opts: RequestOptions = options || {};
    return this.request<T>('DELETE', path, { ...opts, method: 'DELETE' });
  }

  setHeader(name: string, value: string): void {
    this.headers.set(name, value);
  }

  removeHeader(name: string): void {
    this.headers.delete(name);
  }

  private buildHeaders(customHeaders?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {};

    // Add default headers
    this.headers.forEach((value, key) => {
      headers[key] = value;
    });

    // Override with custom headers
    if (customHeaders) {
      Object.assign(headers, customHeaders);
    }

    return headers;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

