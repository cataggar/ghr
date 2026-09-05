import type { IncomingHttpHeaders } from 'node:http';
import * as https from 'node:https';

import { SetupError, errorMessage } from './errors.js';

const API_ORIGIN = 'https://api.github.com';
const RELEASE_REDIRECT_HOSTS = new Set([
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const RETRY_STATUSES = new Set([429, 500, 502, 503, 504]);
const MAX_REDIRECTS = 3;
const MAX_RETRIES = 2;
const REQUEST_TIMEOUT_MS = 15_000;

export interface RequestSpec {
  url: URL;
  method?: 'GET' | 'POST' | 'PUT';
  headers: Record<string, string>;
  body?: Buffer;
  maxBytes: number;
  timeoutMs: number;
}

export interface BufferedResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export type Requester = (request: RequestSpec) => Promise<BufferedResponse>;
export type Sleeper = (milliseconds: number) => Promise<void>;

class TransientRequestError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TransientRequestError';
  }
}

function printableURL(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

function parseContentLength(headers: IncomingHttpHeaders): number | undefined {
  const value = headers['content-length'];
  if (value === undefined) {
    return undefined;
  }
  const text = Array.isArray(value) ? value[0] : value;
  if (!text || !/^(0|[1-9]\d*)$/.test(text)) {
    throw new SetupError('HTTP response has an invalid Content-Length');
  }
  const length = Number(text);
  if (!Number.isSafeInteger(length)) {
    throw new SetupError('HTTP response Content-Length exceeds the supported range');
  }
  return length;
}

export const nodeRequester: Requester = async (spec) =>
  await new Promise<BufferedResponse>((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false, maxSockets: 4 });
    const request = https.request(
      spec.url,
      {
        method: spec.method ?? 'GET',
        headers: spec.headers,
        agent,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        let declaredLength: number | undefined;
        try {
          declaredLength = parseContentLength(response.headers);
          if (declaredLength !== undefined && declaredLength > spec.maxBytes) {
            throw new SetupError(
              `HTTP response is larger than the ${spec.maxBytes}-byte limit`,
            );
          }
        } catch (error) {
          response.destroy();
          reject(error);
          return;
        }
        response.on('data', (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          length += bytes.length;
          if (length > spec.maxBytes) {
            response.destroy(
              new SetupError(`HTTP response is larger than the ${spec.maxBytes}-byte limit`),
            );
            return;
          }
          chunks.push(bytes);
        });
        response.on('error', reject);
        response.on('end', () => {
          if (declaredLength !== undefined && length !== declaredLength) {
            reject(
              new TransientRequestError(
                `HTTP response was truncated: expected ${declaredLength} bytes, received ${length}`,
              ),
            );
            return;
          }
          resolve({
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks, length),
          });
        });
      },
    );
    const timer = setTimeout(() => {
      request.destroy(
        new TransientRequestError(`HTTP request timed out after ${spec.timeoutMs}ms`),
      );
    }, spec.timeoutMs);
    timer.unref();
    request.on('close', () => clearTimeout(timer));
    request.on('error', reject);
    if (spec.body) {
      request.write(spec.body);
    }
    request.end();
  });

async function defaultSleep(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function retryDelay(response: BufferedResponse, attempt: number): number {
  const raw = response.headers['retry-after'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value && /^\d+$/.test(value)) {
    return Math.min(Number(value) * 1000, 2000);
  }
  return 250 * 2 ** attempt;
}

function isAllowedAssetRedirect(url: URL): boolean {
  return (
    url.protocol === 'https:' &&
    url.port === '' &&
    url.username === '' &&
    url.password === '' &&
    url.hash === '' &&
    RELEASE_REDIRECT_HOSTS.has(url.hostname) &&
    url.pathname.startsWith('/github-production-release-asset/')
  );
}

function githubHeaders(accept: string, token: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    'Accept-Encoding': 'identity',
    'User-Agent': 'cataggar-ghr-setup-action',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

export class GitHubHttpClient {
  constructor(
    private readonly token: string | undefined,
    private readonly requester: Requester = nodeRequester,
    private readonly sleep: Sleeper = defaultSleep,
  ) {}

  async getJSON<T>(url: URL, maxBytes = 8 * 1024 * 1024): Promise<{
    value: T;
    headers: IncomingHttpHeaders;
  }> {
    if (url.origin !== API_ORIGIN) {
      throw new SetupError(`refusing non-GitHub API URL: ${printableURL(url)}`);
    }
    const response = await this.requestWithRetries({
      url,
      headers: githubHeaders('application/vnd.github+json', this.token),
      maxBytes,
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    if (response.statusCode !== 200) {
      throw this.httpError(url, response);
    }
    const contentType = response.headers['content-type'];
    const contentTypeText = Array.isArray(contentType) ? contentType[0] : contentType;
    if (contentTypeText && !contentTypeText.toLowerCase().includes('json')) {
      throw new SetupError(
        `GitHub API returned unexpected content type ${contentTypeText} for ${printableURL(url)}`,
      );
    }
    try {
      return {
        value: JSON.parse(response.body.toString('utf8')) as T,
        headers: response.headers,
      };
    } catch (error) {
      throw new SetupError(`GitHub API returned invalid JSON for ${printableURL(url)}`, {
        cause: error,
      });
    }
  }

  async downloadAsset(url: URL, expectedSize: number): Promise<Buffer> {
    if (url.origin !== API_ORIGIN) {
      throw new SetupError(`refusing non-GitHub asset API URL: ${printableURL(url)}`);
    }
    let current = url;
    let authorizationAllowed = true;
    for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
      const response = await this.requestWithRetries({
        url: current,
        headers: githubHeaders(
          'application/octet-stream',
          authorizationAllowed && current.origin === API_ORIGIN ? this.token : undefined,
        ),
        maxBytes: expectedSize,
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      if (REDIRECT_STATUSES.has(response.statusCode)) {
        if (redirects === MAX_REDIRECTS) {
          throw new SetupError('GitHub release asset exceeded the redirect limit');
        }
        const location = response.headers.location;
        const locationText = Array.isArray(location) ? location[0] : location;
        if (!locationText) {
          throw new SetupError('GitHub release asset redirect omitted Location');
        }
        const next = new URL(locationText, current);
        if (next.origin !== current.origin) {
          authorizationAllowed = false;
        }
        if (next.origin !== API_ORIGIN && !isAllowedAssetRedirect(next)) {
          throw new SetupError(
            `refusing unexpected release asset redirect to ${printableURL(next)}`,
          );
        }
        current = next;
        continue;
      }
      if (response.statusCode !== 200) {
        throw this.httpError(current, response);
      }
      const contentEncoding = response.headers['content-encoding'];
      const encodingText = Array.isArray(contentEncoding) ? contentEncoding[0] : contentEncoding;
      if (encodingText && encodingText.toLowerCase() !== 'identity') {
        throw new SetupError(`release asset used unexpected Content-Encoding ${encodingText}`);
      }
      if (response.body.length !== expectedSize) {
        throw new SetupError(
          `release asset size mismatch: metadata says ${expectedSize} bytes, downloaded ${response.body.length}`,
        );
      }
      return response.body;
    }
    throw new SetupError('unreachable release asset redirect state');
  }

  private async requestWithRetries(spec: RequestSpec): Promise<BufferedResponse> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
      try {
        const response = await this.requester(spec);
        if (!RETRY_STATUSES.has(response.statusCode) || attempt === MAX_RETRIES) {
          return response;
        }
        await this.sleep(retryDelay(response, attempt));
      } catch (error) {
        lastError = error;
        if (error instanceof SetupError) {
          throw error;
        }
        if (attempt === MAX_RETRIES) {
          break;
        }
        await this.sleep(250 * 2 ** attempt);
      }
    }
    throw new SetupError(
      `GitHub request failed after ${MAX_RETRIES + 1} attempts: ${errorMessage(lastError)}`,
      { cause: lastError },
    );
  }

  private httpError(url: URL, response: BufferedResponse): SetupError {
    let detail = '';
    try {
      const parsed = JSON.parse(response.body.toString('utf8')) as { message?: unknown };
      if (typeof parsed.message === 'string') {
        detail = `: ${parsed.message.slice(0, 200)}`;
      }
    } catch {
      // Error bodies are intentionally not echoed.
    }
    return new SetupError(
      `GitHub request failed with HTTP ${response.statusCode} for ${printableURL(url)}${detail}`,
    );
  }
}
