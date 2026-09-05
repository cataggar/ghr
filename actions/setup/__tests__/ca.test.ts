import assert from 'node:assert/strict';
import { lstat, mkdir, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { configureCaTrust, type CaTrustIO } from '../src/ca.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/ca');
const certificate =
  '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----';

test.beforeEach(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

function captureIO(): {
  io: CaTrustIO;
  variables: Record<string, string>;
  messages: string[];
} {
  const variables: Record<string, string> = {};
  const messages: string[] = [];
  return {
    variables,
    messages,
    io: {
      exportVariable: (name, value) => {
        variables[name] = value;
      },
      info: (message) => messages.push(message),
    },
  };
}

test('provisions Node roots when a Linux system bundle is absent', async () => {
  const systemBundle = path.join(testRoot, 'etc/ssl/certs/ca-certificates.crt');
  const captured = captureIO();

  await configureCaTrust(testRoot, 'linux', '0.8.0-dev.1', '', captured.io, {
    rootCertificates: [certificate],
    systemBundlePaths: [systemBundle],
  });

  const bundlePath = captured.variables.SSL_CERT_FILE;
  assert.ok(path.isAbsolute(bundlePath));
  assert.equal(await readFile(bundlePath, 'ascii'), `${certificate}\n`);
  assert.equal(await readlink(systemBundle), bundlePath);
  assert.equal((await lstat(systemBundle)).isSymbolicLink(), true);
  assert.match(captured.messages[0], /legacy static ghr/);
});

test('preserves an existing Linux system bundle', async () => {
  const systemBundle = path.join(testRoot, 'etc/ssl/certs/ca-certificates.crt');
  await mkdir(path.dirname(systemBundle), { recursive: true });
  await writeFile(systemBundle, 'existing roots\n');
  const captured = captureIO();

  await configureCaTrust(testRoot, 'linux', '0.8.0', '', captured.io, {
    rootCertificates: [certificate],
    systemBundlePaths: [systemBundle],
  });

  assert.deepEqual(captured.variables, {});
  assert.deepEqual(captured.messages, []);
  assert.equal(await readFile(systemBundle, 'ascii'), 'existing roots\n');
});

test('does not materialize a bundle outside Linux', async () => {
  const captured = captureIO();
  await configureCaTrust(testRoot, 'darwin', '0.8.0', '', captured.io, {
    rootCertificates: [certificate],
    systemBundlePaths: [path.join(testRoot, 'missing.pem')],
  });
  assert.deepEqual(captured.variables, {});
  await assert.rejects(lstat(path.join(testRoot, 'ghr-setup-ca')), /ENOENT/);
});

test('rejects malformed Node root material before publishing trust', async () => {
  const captured = captureIO();
  await assert.rejects(
    configureCaTrust(testRoot, 'linux', '0.8.0', '', captured.io, {
      rootCertificates: ['not a certificate'],
      systemBundlePaths: [path.join(testRoot, 'missing.pem')],
    }),
    /malformed PEM certificate/,
  );
  assert.deepEqual(captured.variables, {});
});

test('current ghr uses SSL_CERT_FILE without changing a system path', async () => {
  const systemBundle = path.join(testRoot, 'etc/ssl/certs/ca-certificates.crt');
  const captured = captureIO();

  await configureCaTrust(testRoot, 'linux', '0.8.0', '', captured.io, {
    rootCertificates: [certificate],
    systemBundlePaths: [systemBundle],
  });

  assert.equal(
    await readFile(captured.variables.SSL_CERT_FILE, 'ascii'),
    `${certificate}\n`,
  );
  await assert.rejects(lstat(systemBundle), /ENOENT/);
  assert.match(captured.messages[0], /static ghr/);
  assert.doesNotMatch(captured.messages[0], /legacy/);
});

test('preserves a configured SSL_CERT_FILE when system trust is absent', async () => {
  const configuredBundle = path.join(testRoot, 'custom-roots.pem');
  const systemBundle = path.join(testRoot, 'etc/ssl/certs/ca-certificates.crt');
  await writeFile(configuredBundle, `${certificate}\n`);
  const captured = captureIO();

  await configureCaTrust(
    testRoot,
    'linux',
    '0.8.0',
    configuredBundle,
    captured.io,
    {
      rootCertificates: ['not used'],
      systemBundlePaths: [systemBundle],
    },
  );

  assert.equal(captured.variables.SSL_CERT_FILE, configuredBundle);
  await assert.rejects(lstat(systemBundle), /ENOENT/);
});
