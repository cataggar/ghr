import assert from 'node:assert/strict';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  CACHED_ARCHIVE_NAME,
  parseTarGzArchive,
  parseZipArchive,
  publishArchive,
  verifyCachedInstallation,
} from '../src/archive.js';
import { sha256Bytes } from '../src/hash.js';
import { makeTarArchive, makeZipArchive } from './helpers.js';

const testRoot = path.resolve(process.cwd(), '../../.tmp/setup-action-tests/archive');

test.before(async () => {
  await rm(testRoot, { recursive: true, force: true });
  await mkdir(testRoot, { recursive: true });
});

test.after(async () => {
  await rm(testRoot, { recursive: true, force: true });
});

test('strict tar and zip parsers accept published layouts', async () => {
  const tar = parseTarGzArchive(
    makeTarArchive(),
    'ghr-1.2.3-linux-musl-x64',
    'ghr',
  );
  assert.equal(tar.binary.toString(), 'test ghr executable\n');
  const zip = await parseZipArchive(
    makeZipArchive(),
    'ghr-1.2.3-windows-x64',
    'ghr.exe',
  );
  assert.equal(zip.binary.toString(), 'test ghr executable\n');
});

test('archive parsers reject traversal and unexpected PATH entries', async () => {
  assert.throws(
    () =>
      parseTarGzArchive(
        makeTarArchive('ghr-1.2.3-linux-musl-x64', [
          {
            name: 'ghr-1.2.3-linux-musl-x64/bin/../escape',
            type: '0',
            data: Buffer.from('x'),
          },
        ]),
        'ghr-1.2.3-linux-musl-x64',
        'ghr',
      ),
    /unsafe archive path/,
  );
  await assert.rejects(
    parseZipArchive(
      makeZipArchive('ghr-1.2.3-windows-x64', [
        {
          name: 'ghr-1.2.3-windows-x64/bin/curl.exe',
          mode: 0o644,
          data: Buffer.from('shadow'),
        },
      ]),
      'ghr-1.2.3-windows-x64',
      'ghr.exe',
    ),
    /unexpected entry/,
  );
});

test('published installation is reverified against the authenticated archive', async () => {
  const archive = makeTarArchive();
  const digest = sha256Bytes(archive);
  const destination = path.join(testRoot, 'valid');
  assert.equal(
    await publishArchive(
      archive,
      'ghr-1.2.3-linux-musl-x64',
      destination,
      'ghr',
      'tar.gz',
    ),
    'published',
  );
  const result = await verifyCachedInstallation(
    destination,
    'ghr-1.2.3-linux-musl-x64',
    archive.length,
    digest,
    'ghr',
    'tar.gz',
  );
  assert.equal((await readFile(result.executablePath)).toString(), 'test ghr executable\n');
});

test('cache corruption fails instead of triggering an unverified fallback', async () => {
  const archive = makeTarArchive();
  const destination = path.join(testRoot, 'corrupt');
  await publishArchive(
    archive,
    'ghr-1.2.3-linux-musl-x64',
    destination,
    'ghr',
    'tar.gz',
  );
  const archivePath = path.join(destination, CACHED_ARCHIVE_NAME);
  const corrupted = await readFile(archivePath);
  corrupted[corrupted.length - 1] ^= 0xff;
  await writeFile(archivePath, corrupted);
  await assert.rejects(
    verifyCachedInstallation(
      destination,
      'ghr-1.2.3-linux-musl-x64',
      archive.length,
      sha256Bytes(archive),
      'ghr',
      'tar.gz',
    ),
    /SHA-256 mismatch/,
  );
});
