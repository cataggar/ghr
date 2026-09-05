import { SetupError } from './errors.js';
import { SHA256_PATTERN } from './hash.js';
import { GitHubHttpClient } from './http.js';
import type { Platform } from './platform.js';

export const RELEASE_OWNER = 'cataggar';
export const RELEASE_REPOSITORY = 'ghr';
export const RELEASE_REPOSITORY_ID = 1_209_370_122;
export const RELEASE_OWNER_ID = '87583576';
export const RELEASE_REPOSITORY_URL = 'https://github.com/cataggar/ghr';
export const RELEASE_WORKFLOW_PATH = '.github/workflows/release.yml';
export const RELEASE_API_ORIGIN = 'https://api.github.com';
export const MAX_ASSET_BYTES = 64 * 1024 * 1024;

export interface ReleaseAsset {
  id: number;
  name: string;
  size: number;
  digest: string;
  apiURL: URL;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SetupError(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new SetupError(`${label} is not a string`);
  }
  return value;
}

function validateAssetURL(value: unknown, assetID: number): URL {
  const url = new URL(string(value, 'release asset API URL'));
  const expectedPath = `/repos/${RELEASE_OWNER}/${RELEASE_REPOSITORY}/releases/assets/${assetID}`;
  if (
    url.origin !== RELEASE_API_ORIGIN ||
    url.pathname !== expectedPath ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new SetupError('release asset API URL does not identify the expected GitHub repository');
  }
  return url;
}

export function selectReleaseAsset(
  releaseValue: unknown,
  tag: string,
  version: string,
  platform: Platform,
): ReleaseAsset {
  const release = record(releaseValue, 'release metadata');
  if (release.tag_name !== tag) {
    throw new SetupError(
      `GitHub returned release tag ${String(release.tag_name)} instead of requested ${tag}`,
    );
  }
  if (release.draft !== false) {
    throw new SetupError(`release ${tag} is a draft or has malformed draft state`);
  }
  if (typeof release.prerelease !== 'boolean') {
    throw new SetupError(`release ${tag} has malformed prerelease state`);
  }
  if (!Array.isArray(release.assets)) {
    throw new SetupError(`release ${tag} has no valid assets list`);
  }

  const expectedName = `ghr-${version}-${platform.target}.${platform.archiveFormat}`;
  const matches = release.assets.filter(
    (candidate) =>
      typeof candidate === 'object' &&
      candidate !== null &&
      !Array.isArray(candidate) &&
      (candidate as Record<string, unknown>).name === expectedName,
  );
  if (matches.length !== 1) {
    throw new SetupError(
      `release ${tag} must contain exactly one ${expectedName} asset; found ${matches.length}`,
    );
  }

  const asset = record(matches[0], `release asset ${expectedName}`);
  if (asset.state !== 'uploaded') {
    throw new SetupError(`release asset ${expectedName} is not in uploaded state`);
  }
  if (!Number.isSafeInteger(asset.id) || (asset.id as number) <= 0) {
    throw new SetupError(`release asset ${expectedName} has an invalid ID`);
  }
  if (
    !Number.isSafeInteger(asset.size) ||
    (asset.size as number) <= 0 ||
    (asset.size as number) > MAX_ASSET_BYTES
  ) {
    throw new SetupError(
      `release asset ${expectedName} size must be between 1 and ${MAX_ASSET_BYTES} bytes`,
    );
  }
  const digestValue = string(asset.digest, `release asset ${expectedName} digest`);
  if (!/^sha256:[0-9a-f]{64}$/.test(digestValue)) {
    throw new SetupError(
      `release asset ${expectedName} must expose a lowercase sha256:<64 hex> digest`,
    );
  }
  const digest = digestValue.slice('sha256:'.length);
  if (!SHA256_PATTERN.test(digest)) {
    throw new SetupError(`release asset ${expectedName} has an invalid SHA-256 digest`);
  }
  const id = asset.id as number;
  return {
    id,
    name: expectedName,
    size: asset.size as number,
    digest,
    apiURL: validateAssetURL(asset.url, id),
  };
}

interface GitObject {
  type: string;
  sha: string;
}

function parseGitObject(value: unknown, label: string): GitObject {
  const object = record(record(value, label).object, `${label}.object`);
  const type = string(object.type, `${label}.object.type`);
  const sha = string(object.sha, `${label}.object.sha`);
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new SetupError(`${label} has an invalid Git object SHA`);
  }
  return { type, sha };
}

export class GhrGitHubClient {
  constructor(private readonly http: GitHubHttpClient) {}

  async getRelease(tag: string): Promise<unknown> {
    const url = new URL(
      `/repos/${RELEASE_OWNER}/${RELEASE_REPOSITORY}/releases/tags/${encodeURIComponent(tag)}`,
      RELEASE_API_ORIGIN,
    );
    return (await this.http.getJSON<unknown>(url)).value;
  }

  async resolveTagCommit(tag: string): Promise<string> {
    const refURL = new URL(
      `/repos/${RELEASE_OWNER}/${RELEASE_REPOSITORY}/git/ref/tags/${encodeURIComponent(tag)}`,
      RELEASE_API_ORIGIN,
    );
    let object = parseGitObject(
      (await this.http.getJSON<unknown>(refURL)).value,
      `tag ref ${tag}`,
    );
    for (let depth = 0; depth < 5; depth += 1) {
      if (object.type === 'commit') {
        return object.sha;
      }
      if (object.type !== 'tag') {
        throw new SetupError(`tag ${tag} resolves to unsupported Git object type ${object.type}`);
      }
      const tagURL = new URL(
        `/repos/${RELEASE_OWNER}/${RELEASE_REPOSITORY}/git/tags/${object.sha}`,
        RELEASE_API_ORIGIN,
      );
      const tagObjectValue = (await this.http.getJSON<unknown>(tagURL)).value;
      const tagObject = record(tagObjectValue, `annotated tag ${object.sha}`);
      if (depth === 0 && tagObject.tag !== tag) {
        throw new SetupError(`annotated tag object does not name requested tag ${tag}`);
      }
      object = parseGitObject(tagObject, `annotated tag ${object.sha}`);
    }
    throw new SetupError(`tag ${tag} contains too many nested annotated tags`);
  }

  async getAttestationBundles(digest: string): Promise<unknown[]> {
    if (!SHA256_PATTERN.test(digest)) {
      throw new SetupError('cannot request attestations for an invalid SHA-256 digest');
    }
    const url = new URL(
      `/repos/${RELEASE_OWNER}/${RELEASE_REPOSITORY}/attestations/sha256:${digest}?per_page=100`,
      RELEASE_API_ORIGIN,
    );
    const response = await this.http.getJSON<unknown>(url);
    const link = response.headers.link;
    const linkText = Array.isArray(link) ? link.join(',') : link;
    if (linkText?.includes('rel="next"')) {
      throw new SetupError('attestation result exceeds the supported 100-bundle limit');
    }
    const body = record(response.value, 'attestation response');
    if (!Array.isArray(body.attestations)) {
      throw new SetupError('attestation response has no valid attestations list');
    }
    if (body.attestations.length === 0) {
      throw new SetupError(`no GitHub attestations exist for sha256:${digest}`);
    }
    return body.attestations.map((entry, index) => {
      const attestation = record(entry, `attestation ${index}`);
      if (attestation.repository_id !== RELEASE_REPOSITORY_ID) {
        throw new SetupError(`attestation ${index} belongs to an unexpected repository`);
      }
      if (!('bundle' in attestation)) {
        throw new SetupError(`attestation ${index} has no Sigstore bundle`);
      }
      return attestation.bundle;
    });
  }

  async downloadAsset(asset: ReleaseAsset): Promise<Buffer> {
    return await this.http.downloadAsset(asset.apiURL, asset.size);
  }
}
