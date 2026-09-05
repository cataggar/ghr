import assert from 'node:assert/strict';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  setup,
  type ActionIO,
  type ReleaseClient,
  type SetupServices,
} from '../src/action.js';
import { type CacheAdapter } from '../src/cache.js';
import { sha256Bytes } from '../src/hash.js';
import { makeTarArchive, releaseMetadata } from './helpers.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/action');
const archive = makeTarArchive();
const digest = sha256Bytes(archive);

test.before(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

function runtime(runnerTemp: string) {
  return {
    actionRef: '0123456789abcdef0123456789abcdef01234567',
    runnerOS: 'Linux',
    runnerArch: 'X64',
    runnerTemp,
    githubServerURL: 'https://github.com',
    githubAPIURL: 'https://api.github.com',
    sslCertFile: '',
    processPlatform: 'linux' as const,
    processArch: 'x64' as const,
  };
}

function captureIO(): {
  io: ActionIO;
  outputs: Record<string, string>;
  variables: Record<string, string>;
  paths: string[];
  states: Record<string, string>;
} {
  const outputs: Record<string, string> = {};
  const variables: Record<string, string> = {};
  const paths: string[] = [];
  const states: Record<string, string> = {};
  return {
    outputs,
    variables,
    paths,
    states,
    io: {
      addPath: (value) => paths.push(value),
      exportVariable: (name, value) => {
        variables[name] = value;
      },
      info: () => {},
      warning: () => {},
      setOutput: (name, value) => {
        outputs[name] = value;
      },
      saveState: (name, value) => {
        states[name] = value;
      },
    },
  };
}

function releaseClient(overrides: Partial<ReleaseClient> = {}): ReleaseClient {
  return {
    getRelease: async () => releaseMetadata(digest, archive.length),
    resolveTagCommit: async () => 'b'.repeat(40),
    getAttestationBundles: async () => [{ bundle: true }],
    downloadAsset: async () => archive,
    ...overrides,
  };
}

function noCache(): CacheAdapter {
  return {
    isFeatureAvailable: () => false,
    restoreCache: async () => undefined,
    saveCache: async () => -1,
  };
}

function services(
  client: ReleaseClient,
  overrides: Partial<SetupServices> = {},
): SetupServices {
  return {
    createReleaseClient: () => client,
    verifyProvenance: async () => {},
    cache: noCache(),
    verifyExecutable: async () => {},
    configureCaTrust: async () => {},
    ...overrides,
  };
}

test('trusted SHA mode installs exactly and emits outputs last', async () => {
  const captured = captureIO();
  let provenanceCalled = false;
  const result = await setup(
    {
      ghrVersion: 'v1.2.3',
      sha256: digest.toUpperCase(),
      token: '',
      cache: 'false',
    },
    runtime(path.join(testRoot, 'success')),
    captured.io,
    services(releaseClient(), {
      verifyProvenance: async () => {
        provenanceCalled = true;
      },
    }),
  );
  assert.equal(provenanceCalled, false);
  assert.deepEqual(captured.outputs, {
    'ghr-path': result.executablePath,
    'ghr-version': 'v1.2.3',
    target: 'linux-musl-x64',
    'cache-hit': 'false',
  });
  assert.deepEqual(captured.paths, [path.dirname(result.executablePath)]);
});

test('provenance is checked before release download', async () => {
  const events: string[] = [];
  await setup(
    { ghrVersion: '1.2.3', sha256: '', token: '', cache: 'false' },
    runtime(path.join(testRoot, 'provenance')),
    captureIO().io,
    services(
      releaseClient({
        resolveTagCommit: async () => {
          events.push('commit');
          return 'b'.repeat(40);
        },
        getAttestationBundles: async () => {
          events.push('attestations');
          return [{}];
        },
        downloadAsset: async () => {
          events.push('download');
          return archive;
        },
      }),
      {
        verifyProvenance: async () => {
          events.push('verify');
        },
      },
    ),
  );
  assert.ok(events.indexOf('verify') < events.indexOf('download'));
});

test('trusted SHA and executable mismatches emit no success outputs', async () => {
  for (const scenario of ['sha', 'executable'] as const) {
    const captured = captureIO();
    await assert.rejects(
      setup(
        {
          ghrVersion: 'v1.2.3',
          sha256: scenario === 'sha' ? '0'.repeat(64) : digest,
          token: '',
          cache: 'false',
        },
        runtime(path.join(testRoot, `mismatch-${scenario}`)),
        captured.io,
        services(releaseClient(), {
          verifyExecutable:
            scenario === 'executable'
              ? async () => {
                  throw new Error('wrong version');
                }
              : async () => {},
        }),
      ),
      scenario === 'sha' ? /does not match/ : /wrong version/,
    );
    assert.deepEqual(captured.outputs, {});
    assert.deepEqual(captured.paths, []);
  }
});

test('missing Linux CA trust emits no success state or outputs', async () => {
  const captured = captureIO();
  await assert.rejects(
    setup(
      {
        ghrVersion: 'v1.2.3',
        sha256: digest,
        token: '',
        cache: 'true',
      },
      runtime(path.join(testRoot, 'ca-trust-failure')),
      captured.io,
      services(releaseClient(), {
        cache: {
          isFeatureAvailable: () => true,
          restoreCache: async () => undefined,
          saveCache: async () => 1,
        },
        configureCaTrust: async () => {
          throw new Error('CA trust unavailable');
        },
      }),
    ),
    /CA trust unavailable/,
  );
  assert.deepEqual(captured.outputs, {});
  assert.deepEqual(captured.paths, []);
  assert.deepEqual(captured.states, {});
});

test('tampered exact cache fails without downloading around corruption', async () => {
  let downloaded = false;
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async () => {
      const tampered = Buffer.from(archive);
      tampered[tampered.length - 1] ^= 0xff;
      return tampered;
    },
    saveCache: async () => 1,
  };
  await assert.rejects(
    setup(
      { ghrVersion: 'v1.2.3', sha256: digest, token: '', cache: 'true' },
      runtime(path.join(testRoot, 'cache-corrupt')),
      captureIO().io,
      services(
        releaseClient({
          downloadAsset: async () => {
            downloaded = true;
            return archive;
          },
        }),
        { cache: adapter },
      ),
    ),
    /SHA-256 mismatch/,
  );
  assert.equal(downloaded, false);
});

test('exact cache hit is reverified and skips the release download', async () => {
  let downloaded = false;
  const adapter: CacheAdapter = {
    isFeatureAvailable: () => true,
    restoreCache: async () => archive,
    saveCache: async () => 1,
  };
  const captured = captureIO();
  const result = await setup(
    { ghrVersion: 'v1.2.3', sha256: digest, token: '', cache: 'true' },
    runtime(path.join(testRoot, 'cache-hit')),
    captured.io,
    services(
      releaseClient({
        downloadAsset: async () => {
          downloaded = true;
          return archive;
        },
      }),
      { cache: adapter },
    ),
  );
  assert.equal(downloaded, false);
  assert.equal(result.cacheHit, true);
  assert.equal(captured.outputs['cache-hit'], 'true');
  assert.deepEqual(captured.states, {});
});
