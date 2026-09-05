import { createHash } from 'node:crypto';

import { SetupError } from './errors.js';
import { nodeRequester, type Requester } from './http.js';
import type { AssetTarget } from './platform.js';

export const CACHE_SCHEMA = 'v1';
export const STATE_CACHE_PATH = 'ghr-cache-path';
export const STATE_CACHE_KEY = 'ghr-cache-key';
export const STATE_EXPECTED_ROOT = 'ghr-cache-expected-root';
export const STATE_ASSET_SIZE = 'ghr-cache-asset-size';
export const STATE_ARCHIVE_DIGEST = 'ghr-cache-archive-digest';
export const STATE_VERSION = 'ghr-cache-version';
export const STATE_CLI_TARGET = 'ghr-cache-cli-target';
export const STATE_EXECUTABLE_NAME = 'ghr-cache-executable-name';
export const STATE_ARCHIVE_FORMAT = 'ghr-cache-archive-format';

const CACHE_VERSION = createHash('sha256')
  .update('ghr-cli-raw-release-archive-v1')
  .digest('hex');
const CACHE_API_MAX_BYTES = 64 * 1024;
const CACHE_TIMEOUT_MS = 30_000;
const RESULTS_HOST_SUFFIX = '.actions.githubusercontent.com';
const BLOB_HOST_SUFFIX = '.blob.core.windows.net';

export interface CacheAdapter {
  isFeatureAvailable(): boolean;
  restoreCache(key: string, expectedSize: number): Promise<Buffer | undefined>;
  saveCache(key: string, archive: Buffer): Promise<number>;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function responseString(
  response: Record<string, unknown>,
  snakeCase: string,
  camelCase: string,
): string | undefined {
  return optionalString(response[snakeCase]) ?? optionalString(response[camelCase]);
}

function validateServiceURL(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.port !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    !url.hostname.endsWith(RESULTS_HOST_SUFFIX)
  ) {
    throw new Error('Actions cache service URL is not an approved HTTPS results endpoint');
  }
  return url;
}

function validateBlobURL(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.port !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    !url.hostname.endsWith(BLOB_HOST_SUFFIX)
  ) {
    throw new SetupError('cache service returned an unapproved signed blob URL');
  }
  return url;
}

function cacheMode(environment: NodeJS.ProcessEnv): string {
  return (environment.ACTIONS_CACHE_MODE ?? '').trim().toLowerCase();
}

function cacheReadable(environment: NodeJS.ProcessEnv): boolean {
  const mode = cacheMode(environment);
  return mode !== 'none' && mode !== 'write-only';
}

function cacheWritable(environment: NodeJS.ProcessEnv): boolean {
  const mode = cacheMode(environment);
  return mode !== 'none' && mode !== 'read';
}

async function parseJSONResponse(
  response: Awaited<ReturnType<Requester>>,
  operation: string,
): Promise<Record<string, unknown>> {
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`${operation} failed with HTTP ${response.statusCode}`);
  }
  try {
    return record(JSON.parse(response.body.toString('utf8')), `${operation} response`);
  } catch (error) {
    throw new Error(`${operation} returned invalid JSON`, { cause: error });
  }
}

export class ActionsCacheV2 implements CacheAdapter {
  constructor(
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly requester: Requester = nodeRequester,
  ) {}

  isFeatureAvailable(): boolean {
    return Boolean(
      this.environment.ACTIONS_CACHE_SERVICE_V2 &&
        this.environment.ACTIONS_RESULTS_URL &&
        this.environment.ACTIONS_RUNTIME_TOKEN,
    );
  }

  async restoreCache(key: string, expectedSize: number): Promise<Buffer | undefined> {
    if (!this.isFeatureAvailable() || !cacheReadable(this.environment)) {
      return undefined;
    }
    const response = await this.rpc('GetCacheEntryDownloadURL', {
      key,
      restore_keys: [],
      version: CACHE_VERSION,
    });
    if (response.ok !== true) {
      return undefined;
    }
    const matchedKey = responseString(response, 'matched_key', 'matchedKey');
    if (matchedKey !== key) {
      throw new SetupError(
        `cache service returned unexpected key ${matchedKey ?? '<missing>'}; exact key ${key} was required`,
      );
    }
    const signedURL = responseString(
      response,
      'signed_download_url',
      'signedDownloadUrl',
    );
    if (!signedURL) {
      throw new SetupError('exact cache hit did not include a signed download URL');
    }

    try {
      const download = await this.requester({
        url: validateBlobURL(signedURL),
        method: 'GET',
        headers: {
          Accept: 'application/octet-stream',
          'Accept-Encoding': 'identity',
          'User-Agent': 'cataggar-ghr-setup-action',
        },
        maxBytes: expectedSize,
        timeoutMs: CACHE_TIMEOUT_MS,
      });
      if (download.statusCode !== 200) {
        throw new Error(`exact cache download failed with HTTP ${download.statusCode}`);
      }
      if (download.body.length !== expectedSize) {
        throw new SetupError(
          `exact cache archive size mismatch: expected ${expectedSize}, received ${download.body.length}`,
        );
      }
      return download.body;
    } catch (error) {
      if (error instanceof SetupError) {
        throw error;
      }
      throw new Error('exact cache hit could not be downloaded', { cause: error });
    }
  }

  async saveCache(key: string, archive: Buffer): Promise<number> {
    if (!this.isFeatureAvailable() || !cacheWritable(this.environment)) {
      return -1;
    }
    const create = await this.rpc('CreateCacheEntry', {
      key,
      version: CACHE_VERSION,
    });
    if (create.ok !== true) {
      throw new Error('cache entry could not be reserved');
    }
    const signedURL = responseString(create, 'signed_upload_url', 'signedUploadUrl');
    if (!signedURL) {
      throw new Error('cache reservation omitted its signed upload URL');
    }
    const upload = await this.requester({
      url: validateBlobURL(signedURL),
      method: 'PUT',
      headers: {
        'Content-Length': String(archive.length),
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'cataggar-ghr-setup-action',
        'x-ms-blob-type': 'BlockBlob',
        'x-ms-version': '2020-04-08',
      },
      body: archive,
      maxBytes: CACHE_API_MAX_BYTES,
      timeoutMs: CACHE_TIMEOUT_MS,
    });
    if (upload.statusCode < 200 || upload.statusCode >= 300) {
      throw new Error(`cache upload failed with HTTP ${upload.statusCode}`);
    }

    const finalize = await this.rpc('FinalizeCacheEntryUpload', {
      key,
      version: CACHE_VERSION,
      size_bytes: String(archive.length),
    });
    if (finalize.ok !== true) {
      throw new Error('cache upload could not be finalized');
    }
    const entryID = responseString(finalize, 'entry_id', 'entryId');
    if (!entryID || !/^\d+$/.test(entryID)) {
      return 0;
    }
    const value = Number(entryID);
    return Number.isSafeInteger(value) ? value : 0;
  }

  private async rpc(
    method:
      | 'CreateCacheEntry'
      | 'FinalizeCacheEntryUpload'
      | 'GetCacheEntryDownloadURL',
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const baseURL = validateServiceURL(this.environment.ACTIONS_RESULTS_URL ?? '');
    const token = this.environment.ACTIONS_RUNTIME_TOKEN;
    if (!token) {
      throw new Error('Actions cache runtime token is unavailable');
    }
    const body = Buffer.from(JSON.stringify(payload));
    const url = new URL(
      `/twirp/github.actions.results.api.v1.CacheService/${method}`,
      baseURL,
    );
    const response = await this.requester({
      url,
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        Authorization: `Bearer ${token}`,
        'Content-Length': String(body.length),
        'Content-Type': 'application/json',
        'User-Agent': 'cataggar-ghr-setup-action',
      },
      body,
      maxBytes: CACHE_API_MAX_BYTES,
      timeoutMs: CACHE_TIMEOUT_MS,
    });
    return await parseJSONResponse(response, `Actions cache ${method}`);
  }
}

export const defaultCacheAdapter: CacheAdapter = new ActionsCacheV2();

export function parseCacheInput(value: string): boolean {
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  throw new SetupError(`cache must be exactly "true" or "false", received ${JSON.stringify(value)}`);
}

export function cacheKey(target: AssetTarget, tag: string, digest: string): string {
  return `ghr-cli-${CACHE_SCHEMA}-${target}-${tag}-${digest}`;
}
