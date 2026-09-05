import assert from 'node:assert/strict';
import test from 'node:test';

import { cacheKey, parseCacheInput } from '../src/cache.js';
import { clearAmbientConfiguration } from '../src/environment.js';
import { normalizeTrustedSha256 } from '../src/hash.js';
import { normalizePlatform } from '../src/platform.js';
import { resolveVersion } from '../src/version.js';

test('explicit exact version wins and exact action tags derive', () => {
  assert.deepEqual(resolveVersion('v1.2.3-rc.1+build.7', 'deadbeef'), {
    version: '1.2.3-rc.1+build.7',
    tag: 'v1.2.3-rc.1+build.7',
    source: 'input',
  });
  assert.deepEqual(resolveVersion('', 'v2.0.0-beta.2'), {
    version: '2.0.0-beta.2',
    tag: 'v2.0.0-beta.2',
    source: 'action-ref',
  });
});

test('ambiguous versions and refs are rejected', () => {
  for (const value of ['latest', '1.x', '^1.2.3', 'v1', 'v1.2', ' v1.2.3']) {
    assert.throws(() => resolveVersion(value, ''), /exact SemVer/);
  }
  for (const ref of ['', 'main', '0123456789abcdef0123456789abcdef01234567']) {
    assert.throws(() => resolveVersion('', ref), /required|exact v-prefixed SemVer/);
  }
});

test('runner target and Node process must agree', () => {
  assert.deepEqual(normalizePlatform('Linux', 'X64', 'linux', 'x64'), {
    target: 'linux-musl-x64',
    cliTarget: 'linux-x86_64-musl',
    archiveFormat: 'tar.gz',
    executableName: 'ghr',
  });
  assert.equal(
    normalizePlatform('macOS', 'ARM64', 'darwin', 'arm64').target,
    'macos-arm64',
  );
  assert.equal(
    normalizePlatform('Windows', 'X64', 'win32', 'x64').target,
    'windows-x64',
  );
  assert.throws(() => normalizePlatform('Linux', 'ARM', 'linux', 'arm'), /unsupported/);
  assert.throws(() => normalizePlatform('Linux', 'X64', 'linux', 'arm64'), /mismatch/);
});

test('trusted SHA, cache input, and key are strict', () => {
  assert.equal(normalizeTrustedSha256('A'.repeat(64)), 'a'.repeat(64));
  assert.equal(parseCacheInput('true'), true);
  assert.equal(parseCacheInput('false'), false);
  assert.throws(() => parseCacheInput('TRUE'), /exactly/);
  assert.throws(() => normalizeTrustedSha256('a'.repeat(63)), /64 hexadecimal/);
  assert.equal(
    cacheKey('linux-musl-x64', 'v1.2.3', 'a'.repeat(64)),
    `ghr-cli-v1-linux-musl-x64-v1.2.3-${'a'.repeat(64)}`,
  );
});

test('ambient proxy and credential configuration is removed', () => {
  const environment: NodeJS.ProcessEnv = {
    HTTP_PROXY: 'http://proxy.invalid',
    GH_TOKEN: 'secret',
    GIT_CONFIG_GLOBAL: '/untrusted/config',
    SAFE_VALUE: 'kept',
  };
  clearAmbientConfiguration(environment);
  assert.deepEqual(environment, { SAFE_VALUE: 'kept' });
});
