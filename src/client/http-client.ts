import { SignClient, type SignClientConfig } from './signer.js';

export interface SignedHttpClientConfig extends SignClientConfig {
  baseUrl: string;
  /**
   * Default headers merged into every request. Callers can override per
   * call. The signature header is added LAST so user headers can never
   * shadow it.
   */
  defaultHeaders?: Record<string, string>;
  /**
   * Optional fetch implementation. Defaults to global `fetch` (Node 18+).
   * Pass a node-fetch / undici instance if you need custom agents.
   */
  fetch?: typeof globalThis.fetch;
  /**
   * Request timeout in milliseconds. Defaults to 30s. Implemented with
   * `AbortController`, so it covers DNS + TCP + TLS + body read.
   */
  timeoutMs?: number;
}

export interface SignedRequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Thin fetch wrapper that signs every outgoing request with the configured
 * client/secret. Use this when you don't already have a preferred HTTP
 * client; otherwise use `SignClient` directly with axios/got/etc.
 *
 * KEY INVARIANT: the body bytes used to compute the signature are EXACTLY
 * the bytes sent on the wire. We achieve this by serializing the body
 * exactly ONCE inside `request()` and reusing the serialized string.
 */
export class SignedHttpClient {
  readonly #signer: SignClient;
  readonly #baseUrl: string;
  readonly #defaultHeaders: Record<string, string>;
  readonly #fetch: typeof globalThis.fetch;
  readonly #defaultTimeoutMs: number;

  constructor(config: SignedHttpClientConfig) {
    if (!config.baseUrl) throw new Error('SignedHttpClient: baseUrl required');
    this.#signer = new SignClient(config);
    // Strip trailing slash so we can always concat with a leading-slash path.
    this.#baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.#defaultHeaders = config.defaultHeaders ?? {};
    this.#fetch = config.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') {
      throw new Error(
        'SignedHttpClient: global fetch is unavailable. Pass `fetch` in config (Node <18 or non-standard runtime).',
      );
    }
    this.#defaultTimeoutMs = config.timeoutMs ?? 30_000;
  }

  /** Low-level signed fetch. Returns the standard Response object. */
  async request(
    method: string,
    path: string,
    body?: unknown,
    options: SignedRequestOptions = {},
  ): Promise<Response> {
    // 1. Serialize body ONCE. Any later re-serialization breaks the hash.
    const { bodyString, contentType } = serializeBody(body);

    // 2. Build the path that will be SIGNED. Query string IS included
    //    because it's part of the request semantics. The verifier must
    //    use the same convention (we document it in the README).
    const queryString = buildQueryString(options.query);
    const fullPath = queryString ? `${path}?${queryString}` : path;

    // 3. Sign. The signature covers method + path-with-query + body bytes.
    const signed = this.#signer.sign({
      method,
      path: fullPath,
      body: bodyString,
    });

    // 4. Compose headers. Sig header goes last to win any conflict.
    const headers: Record<string, string> = {
      ...this.#defaultHeaders,
      ...(options.headers ?? {}),
    };
    if (bodyString && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = contentType;
    }
    headers[signed.headerName] = signed.headerValue;

    // 5. Compose abort signal. We respect external `options.signal` AND
    //    add our own timeout. Whichever fires first wins.
    const timeoutMs = options.timeoutMs ?? this.#defaultTimeoutMs;
    const internalAbort = new AbortController();
    const timer = setTimeout(() => internalAbort.abort(), timeoutMs);
    const signal = options.signal
      ? anySignal([options.signal, internalAbort.signal])
      : internalAbort.signal;

    try {
      return await this.#fetch(`${this.#baseUrl}${fullPath}`, {
        method,
        headers,
        body: bodyString || undefined,
        signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  get(path: string, options?: SignedRequestOptions): Promise<Response> {
    return this.request('GET', path, undefined, options);
  }
  post(
    path: string,
    body?: unknown,
    options?: SignedRequestOptions,
  ): Promise<Response> {
    return this.request('POST', path, body, options);
  }
  put(
    path: string,
    body?: unknown,
    options?: SignedRequestOptions,
  ): Promise<Response> {
    return this.request('PUT', path, body, options);
  }
  patch(
    path: string,
    body?: unknown,
    options?: SignedRequestOptions,
  ): Promise<Response> {
    return this.request('PATCH', path, body, options);
  }
  delete(
    path: string,
    body?: unknown,
    options?: SignedRequestOptions,
  ): Promise<Response> {
    return this.request('DELETE', path, body, options);
  }
}

/** Serialize a request body to a single canonical string + Content-Type. */
function serializeBody(body: unknown): {
  bodyString: string;
  contentType: string;
} {
  if (body === undefined || body === null) {
    return { bodyString: '', contentType: 'application/json' };
  }
  if (typeof body === 'string') {
    return { bodyString: body, contentType: 'text/plain;charset=utf-8' };
  }
  if (Buffer.isBuffer(body)) {
    return {
      bodyString: body.toString('utf8'),
      contentType: 'application/octet-stream',
    };
  }
  // Default: JSON. We stringify with NO indentation so the bytes are
  // deterministic across Node versions.
  return {
    bodyString: JSON.stringify(body),
    contentType: 'application/json',
  };
}

function buildQueryString(
  q?: Record<string, string | number | boolean | undefined>,
): string {
  if (!q) return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined) continue;
    params.append(k, String(v));
  }
  return params.toString();
}

/** Combine multiple AbortSignals into one. Polyfill of `AbortSignal.any`. */
function anySignal(signals: AbortSignal[]): AbortSignal {
  // Use native if available (Node 20+).
  const anyFn = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === 'function') return anyFn(signals);
  const ctrl = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      ctrl.abort(s.reason);
      return ctrl.signal;
    }
    s.addEventListener('abort', () => ctrl.abort(s.reason), { once: true });
  }
  return ctrl.signal;
}
