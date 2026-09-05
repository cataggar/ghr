import * as core from '@actions/core';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import {
  exists,
  publishArchive,
  verifyCachedInstallation,
} from './archive.js';
import {
  STATE_ARCHIVE_DIGEST,
  STATE_ARCHIVE_FORMAT,
  STATE_ASSET_SIZE,
  STATE_CACHE_KEY,
  STATE_CACHE_PATH,
  STATE_CLI_TARGET,
  STATE_EXECUTABLE_NAME,
  STATE_EXPECTED_ROOT,
  STATE_VERSION,
  cacheKey,
  defaultCacheAdapter,
  parseCacheInput,
  type CacheAdapter,
} from './cache.js';
import { configureDirectNetwork } from './environment.js';
import { SetupError, errorMessage } from './errors.js';
import {
  GhrGitHubClient,
  selectReleaseAsset,
  type ReleaseAsset,
} from './github.js';
import { normalizeTrustedSha256, sha256Bytes } from './hash.js';
import { GitHubHttpClient } from './http.js';
import { normalizePlatform, type Platform } from './platform.js';
import { verifyProvenance as verifyReleaseProvenance } from './provenance.js';
import {
  verifyInstallation as verifyExecutable,
  type InstallationRunner,
} from './runner.js';
import { resolveVersion, type ResolvedVersion } from './version.js';

export interface SetupInputs {
  ghrVersion: string;
  sha256: string;
  token: string;
  cache: string;
}

export interface RuntimeEnvironment {
  actionRef: string;
  runnerOS: string;
  runnerArch: string;
  runnerTemp: string;
  githubServerURL: string;
  githubAPIURL: string;
  processPlatform: NodeJS.Platform;
  processArch: NodeJS.Architecture;
}

export interface ActionIO {
  addPath(path: string): void;
  info(message: string): void;
  warning(message: string): void;
  setOutput(name: string, value: string): void;
  saveState(name: string, value: string): void;
}

export interface ReleaseClient {
  getRelease(tag: string): Promise<unknown>;
  resolveTagCommit(tag: string): Promise<string>;
  getAttestationBundles(digest: string): Promise<unknown[]>;
  downloadAsset(asset: ReleaseAsset): Promise<Buffer>;
}

export interface SetupServices {
  createReleaseClient(token: string | undefined): ReleaseClient;
  verifyProvenance(
    bundles: unknown[],
    expected: {
      tag: string;
      assetName: string;
      digest: string;
      commit: string;
    },
    tufCachePath: string,
  ): Promise<void>;
  cache: CacheAdapter;
  verifyExecutable: InstallationRunner;
}

export interface SetupResult {
  executablePath: string;
  version: ResolvedVersion;
  platform: Platform;
  cacheHit: boolean;
}

export const defaultActionIO: ActionIO = {
  addPath: (value) => core.addPath(value),
  info: (message) => core.info(message),
  warning: (message) => core.warning(message),
  setOutput: (name, value) => core.setOutput(name, value),
  saveState: (name, value) => core.saveState(name, value),
};

export const defaultServices: SetupServices = {
  createReleaseClient: (token) =>
    new GhrGitHubClient(new GitHubHttpClient(token)),
  verifyProvenance: verifyReleaseProvenance,
  cache: defaultCacheAdapter,
  verifyExecutable,
};

function validateRuntime(environment: RuntimeEnvironment): string {
  if (
    environment.githubServerURL &&
    environment.githubServerURL !== 'https://github.com'
  ) {
    throw new SetupError(
      `unsupported GitHub server ${environment.githubServerURL}; GHES mirroring is not supported`,
    );
  }
  if (
    environment.githubAPIURL &&
    environment.githubAPIURL !== 'https://api.github.com'
  ) {
    throw new SetupError(
      `unsupported GitHub API ${environment.githubAPIURL}; only https://api.github.com is supported`,
    );
  }
  if (!path.isAbsolute(environment.runnerTemp)) {
    throw new SetupError('RUNNER_TEMP must be an absolute path');
  }
  return path.resolve(environment.runnerTemp);
}

function validateToken(value: string): string | undefined {
  if (value.length === 0) {
    return undefined;
  }
  if (value !== value.trim() || value.includes('\r') || value.includes('\n')) {
    throw new SetupError('token must not contain whitespace or line breaks');
  }
  return value;
}

function installationRoot(
  runnerTemp: string,
  version: ResolvedVersion,
  platform: Platform,
  digest: string,
): string {
  const root = path.resolve(
    runnerTemp,
    'ghr-setup',
    version.version,
    platform.target,
    digest,
  );
  const relative = path.relative(runnerTemp, root);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new SetupError('computed installation path escapes RUNNER_TEMP');
  }
  return root;
}

async function verifyInstallation(
  root: string,
  archiveRoot: string,
  asset: ReleaseAsset,
  version: string,
  platform: Platform,
  runner: InstallationRunner,
): Promise<string> {
  const verified = await verifyCachedInstallation(
    root,
    archiveRoot,
    asset.size,
    asset.digest,
    platform.executableName,
    platform.archiveFormat,
  );
  await runner(verified.executablePath, version, platform.cliTarget);
  return verified.executablePath;
}

export async function setup(
  inputs: SetupInputs,
  environment: RuntimeEnvironment,
  io: ActionIO = defaultActionIO,
  services: SetupServices = defaultServices,
): Promise<SetupResult> {
  const runnerTemp = validateRuntime(environment);
  const token = validateToken(inputs.token);
  const version = resolveVersion(inputs.ghrVersion, environment.actionRef);
  const platform = normalizePlatform(
    environment.runnerOS,
    environment.runnerArch,
    environment.processPlatform,
    environment.processArch,
  );
  const trustedSha256 = normalizeTrustedSha256(inputs.sha256);
  const cacheEnabled = parseCacheInput(inputs.cache);
  const actionTemp = path.join(runnerTemp, 'ghr-setup-tmp');
  const tufCachePath = path.join(runnerTemp, 'ghr-sigstore-tuf-v1');
  await mkdir(actionTemp, { recursive: true, mode: 0o700 });

  const github = services.createReleaseClient(token);
  const release = await github.getRelease(version.tag);
  const asset = selectReleaseAsset(release, version.tag, version.version, platform);
  if (trustedSha256 && trustedSha256 !== asset.digest) {
    throw new SetupError(
      `trusted sha256 ${trustedSha256} does not match GitHub's asset digest ${asset.digest}`,
    );
  }

  if (trustedSha256) {
    io.info(`Using caller-supplied trusted SHA-256 for ${asset.name}`);
  } else {
    const [commit, bundles] = await Promise.all([
      github.resolveTagCommit(version.tag),
      github.getAttestationBundles(asset.digest),
    ]);
    await services.verifyProvenance(
      bundles,
      {
        tag: version.tag,
        assetName: asset.name,
        digest: asset.digest,
        commit,
      },
      tufCachePath,
    );
    io.info(`Verified GitHub release provenance for ${asset.name}`);
  }

  const archiveRoot = `ghr-${version.version}-${platform.target}`;
  const root = installationRoot(runnerTemp, version, platform, asset.digest);
  const key = cacheKey(platform.target, version.tag, asset.digest);
  let cacheHit = false;
  let published = false;
  let executablePath: string;

  if (await exists(root)) {
    executablePath = await verifyInstallation(
      root,
      archiveRoot,
      asset,
      version.version,
      platform,
      services.verifyExecutable,
    );
    io.info('Reused an already-present, reverified ghr installation');
  } else {
    if (cacheEnabled) {
      try {
        const cachedArchive = await services.cache.restoreCache(key, asset.size);
        if (cachedArchive) {
          const cachedDigest = sha256Bytes(cachedArchive);
          if (cachedDigest !== asset.digest) {
            throw new SetupError(
              `cached release archive SHA-256 mismatch: expected ${asset.digest}, found ${cachedDigest}`,
            );
          }
          const publishResult = await publishArchive(
            cachedArchive,
            archiveRoot,
            root,
            platform.executableName,
            platform.archiveFormat,
          );
          if (publishResult === 'raced') {
            io.info('A parallel invocation published the same verified ghr installation');
          }
          cacheHit = true;
        }
      } catch (error) {
        if (error instanceof SetupError) {
          throw error;
        }
        io.warning(`Could not restore the optional ghr CLI cache: ${errorMessage(error)}`);
      }
    }

    if (cacheHit) {
      executablePath = await verifyInstallation(
        root,
        archiveRoot,
        asset,
        version.version,
        platform,
        services.verifyExecutable,
      );
      io.info(`Restored and reverified ${asset.name} from the exact CLI cache`);
    } else {
      const archive = await github.downloadAsset(asset);
      const downloadedDigest = sha256Bytes(archive);
      if (downloadedDigest !== asset.digest) {
        throw new SetupError(
          `downloaded release asset SHA-256 mismatch: expected ${asset.digest}, found ${downloadedDigest}`,
        );
      }
      const publishResult = await publishArchive(
        archive,
        archiveRoot,
        root,
        platform.executableName,
        platform.archiveFormat,
      );
      published = publishResult === 'published';
      if (publishResult === 'raced') {
        io.info('A parallel invocation published the same verified ghr installation');
      }
      executablePath = await verifyInstallation(
        root,
        archiveRoot,
        asset,
        version.version,
        platform,
        services.verifyExecutable,
      );
      io.info(`Downloaded and verified ${asset.name}`);
    }
  }

  if (
    cacheEnabled &&
    !cacheHit &&
    published &&
    services.cache.isFeatureAvailable()
  ) {
    io.saveState(STATE_CACHE_PATH, root);
    io.saveState(STATE_CACHE_KEY, key);
    io.saveState(STATE_EXPECTED_ROOT, archiveRoot);
    io.saveState(STATE_ASSET_SIZE, String(asset.size));
    io.saveState(STATE_ARCHIVE_DIGEST, asset.digest);
    io.saveState(STATE_VERSION, version.version);
    io.saveState(STATE_CLI_TARGET, platform.cliTarget);
    io.saveState(STATE_EXECUTABLE_NAME, platform.executableName);
    io.saveState(STATE_ARCHIVE_FORMAT, platform.archiveFormat);
  }

  io.addPath(path.dirname(executablePath));
  io.setOutput('ghr-path', executablePath);
  io.setOutput('ghr-version', version.tag);
  io.setOutput('target', platform.target);
  io.setOutput('cache-hit', cacheHit ? 'true' : 'false');

  return { executablePath, version, platform, cacheHit };
}

export function readInputs(): SetupInputs {
  return {
    ghrVersion: core.getInput('ghr-version', { trimWhitespace: false }),
    sha256: core.getInput('sha256', { trimWhitespace: false }),
    token: core.getInput('token', { trimWhitespace: false }),
    cache: core.getInput('cache', { trimWhitespace: false }) || 'true',
  };
}

export function readRuntimeEnvironment(): RuntimeEnvironment {
  return {
    actionRef: process.env.GITHUB_ACTION_REF ?? '',
    runnerOS: process.env.RUNNER_OS ?? '',
    runnerArch: process.env.RUNNER_ARCH ?? '',
    runnerTemp: process.env.RUNNER_TEMP ?? '',
    githubServerURL: process.env.GITHUB_SERVER_URL ?? '',
    githubAPIURL: process.env.GITHUB_API_URL ?? '',
    processPlatform: process.platform,
    processArch: process.arch,
  };
}

export async function runMain(): Promise<void> {
  try {
    const inputs = readInputs();
    if (inputs.token) {
      core.setSecret(inputs.token);
    }
    const environment = readRuntimeEnvironment();
    const runnerTemp = validateRuntime(environment);
    process.env.TMPDIR = path.join(runnerTemp, 'ghr-setup-tmp');
    process.env.TMP = process.env.TMPDIR;
    process.env.TEMP = process.env.TMPDIR;
    delete process.env.INPUT_TOKEN;
    configureDirectNetwork();
    await setup(inputs, environment);
  } catch (error) {
    core.setFailed(errorMessage(error));
  }
}
