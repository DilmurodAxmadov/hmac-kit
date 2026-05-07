import { EdgeSignClient, type EdgeSignClientConfig } from './signer-web.js';

export interface EdgeRetryConfig {
  attempts: number;
  delayMs: number;
  backoff: 'fixed' | 'exponential';
  statusCodes: number[];
}

const DEFAULT_EDGE_RETRY: EdgeRetryConfig = {
  attempts: 1,
  delayMs: 500,
  backoff: 'exponential',
  statusCodes: [429, 500, 502, 503, 504],
};

export interface EdgeSignedHttpClientConfig extends EdgeSignClientConfig {
  baseUrl: string;
  defaultHeaders?: Record<string, string>;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  retry?: Partial<EdgeRetryConfig>;
}

export interface EdgeSignedRequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Edge-compatible signed HTTP client. Uses Web Crypto via `EdgeSignClient`.
 * Works in Cloudflare Workers, Deno, Vercel Edge Runtime, and Node.js 18+.
 */
export class EdgeSignedHttpClient {
  readonly #signer: EdgeSignClient;
  readonly #baseUrl: string;
  readonly #defaultHeaders: Record<string, string>;
  readonly #fetch: typeof globalThis.fetch;
  readonly #defaultTimeoutMs: number;
  readonly #retry: EdgeRetryConfig;

  constructor(config: EdgeSignedHttpClientConfig) {
    if (!config.baseUrl) throw new Error('EdgeSignedHttpClient: baseUrl required');
    this.#signer = new EdgeSignClient(config);
    this.#baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.#defaultHeaders = config.defaultHeaders ?? {};
    this.#fetch = config.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') {
      throw new Error('EdgeSignedHttpClient: global fetch is unavailable. Pass `fetch` in config.');
    }
    this.#defaultTimeoutMs = config.timeoutMs ?? 30_000;
    this.#retry = { ...DEFAULT_EDGE_RETRY, ...config.retry };
  }

  async request(
    method: string,
    path: string,
    body?: unknown,
    options: EdgeSignedRequestOptions = {},
  ): Promise<Response> {
    const { bodyString, contentType } = serializeBody(body);
    const queryString = buildQueryString(options.query);
    const fullPath = queryString ? `${path}?${queryString}` : path;

    let lastError: unknown;

    for (let attempt = 0; attempt < this.#retry.attempts; attempt++) {
      if (attempt > 0) {
        const delay =
          this.#retry.backoff === 'exponential'
            ? this.#retry.delayMs * 2 ** (attempt - 1)
            : this.#retry.delayMs;
        await sleep(delay);
      }

      const signed = await this.#signer.sign({
        method,
        path: fullPath,
        body: bodyString,
      });

      const headers: Record<string, string> = {
        ...this.#defaultHeaders,
        ...(options.headers ?? {}),
      };
      if (bodyString && !headers['Content-Type'] && !headers['content-type']) {
        headers['Content-Type'] = contentType;
      }
      headers[signed.headerName] = signed.headerValue;

      const timeoutMs = options.timeoutMs ?? this.#defaultTimeoutMs;
      const internalAbort = new AbortController();
      const timer = setTimeout(() => internalAbort.abort(), timeoutMs);
      const signal = options.signal
        ? anySignal([options.signal, internalAbort.signal])
        : internalAbort.signal;

      try {
        const response = await this.#fetch(`${this.#baseUrl}${fullPath}`, {
          method,
          headers,
          body: bodyString || undefined,
          signal,
        });

        const isLast = attempt === this.#retry.attempts - 1;
        if (!isLast && this.#retry.statusCodes.includes(response.status)) {
          response.body?.cancel();
          lastError = new Error(`HTTP ${response.status}`);
          continue;
        }

        return response;
      } catch (err) {
        lastError = err;
        if (attempt === this.#retry.attempts - 1) throw err;
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError;
  }

  get(path: string, options?: EdgeSignedRequestOptions): Promise<Response> {
    return this.request('GET', path, undefined, options);
  }
  post(path: string, body?: unknown, options?: EdgeSignedRequestOptions): Promise<Response> {
    return this.request('POST', path, body, options);
  }
  put(path: string, body?: unknown, options?: EdgeSignedRequestOptions): Promise<Response> {
    return this.request('PUT', path, body, options);
  }
  patch(path: string, body?: unknown, options?: EdgeSignedRequestOptions): Promise<Response> {
    return this.request('PATCH', path, body, options);
  }
  delete(path: string, body?: unknown, options?: EdgeSignedRequestOptions): Promise<Response> {
    return this.request('DELETE', path, body, options);
  }
}

function serializeBody(body: unknown): { bodyString: string; contentType: string } {
  if (body === undefined || body === null) return { bodyString: '', contentType: 'application/json' };
  if (typeof body === 'string') return { bodyString: body, contentType: 'text/plain;charset=utf-8' };
  if (body instanceof Uint8Array) return { bodyString: new TextDecoder().decode(body), contentType: 'application/octet-stream' };
  return { bodyString: JSON.stringify(body), contentType: 'application/json' };
}

function buildQueryString(q?: Record<string, string | number | boolean | undefined>): string {
  if (!q) return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined) continue;
    params.append(k, String(v));
  }
  return params.toString();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  const anyFn = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === 'function') return anyFn(signals);
  const ctrl = new AbortController();
  for (const s of signals) {
    if (s.aborted) { ctrl.abort(s.reason); return ctrl.signal; }
    s.addEventListener('abort', () => ctrl.abort(s.reason), { once: true });
  }
  return ctrl.signal;
}
