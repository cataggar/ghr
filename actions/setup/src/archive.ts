import { randomUUID } from 'node:crypto';
import type { Stats } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import yauzl, { type Entry, type ZipFile } from 'yauzl';

import { SetupError, errorMessage } from './errors.js';
import { sha256Bytes } from './hash.js';
import type { ArchiveFormat } from './platform.js';

export const CACHED_ARCHIVE_NAME = '.ghr-release-archive';
const TAR_BLOCK_SIZE = 512;
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 96 * 1024 * 1024;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 16;

export interface ArchiveEntry {
  relativePath: string;
  type: 'directory' | 'file';
  mode: 0o644 | 0o755;
  data?: Buffer;
}

export interface ArchiveManifest {
  entries: ArchiveEntry[];
  binary: Buffer;
  binaryDigest: string;
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function decodeString(field: Buffer, label: string): string {
  const terminator = field.indexOf(0);
  const end = terminator === -1 ? field.length : terminator;
  if (terminator !== -1 && field.subarray(terminator).some((byte) => byte !== 0)) {
    throw new SetupError(`${label} has nonzero bytes after its terminator`);
  }
  const value = field.subarray(0, end);
  if (value.some((byte) => byte < 0x20 || byte > 0x7e)) {
    throw new SetupError(`${label} is not printable ASCII`);
  }
  return value.toString('ascii');
}

function parseOctal(field: Buffer, label: string): number {
  if ((field[0] ?? 0) & 0x80) {
    throw new SetupError(`${label} uses unsupported base-256 encoding`);
  }
  const text = field.toString('ascii').replace(/[\0 ]+$/u, '').replace(/^ +/u, '');
  if (!/^[0-7]+$/.test(text)) {
    throw new SetupError(`${label} is not canonical octal`);
  }
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) {
    throw new SetupError(`${label} exceeds the supported integer range`);
  }
  return value;
}

function validateChecksum(header: Buffer): void {
  const expected = parseOctal(header.subarray(148, 156), 'tar header checksum');
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index] ?? 0;
  }
  if (actual !== expected) {
    throw new SetupError(`tar header checksum mismatch: expected ${expected}, calculated ${actual}`);
  }
}

function safeArchivePath(rawName: string, expectedRoot: string): {
  normalized: string;
  relative: string;
} {
  if (
    rawName.length === 0 ||
    rawName.startsWith('/') ||
    rawName.startsWith('\\') ||
    /^[A-Za-z]:/.test(rawName) ||
    rawName.includes('\\') ||
    rawName.includes('\0')
  ) {
    throw new SetupError(`unsafe archive path ${JSON.stringify(rawName)}`);
  }
  const normalized = rawName.endsWith('/') ? rawName.slice(0, -1) : rawName;
  const parts = normalized.split('/');
  if (
    normalized.length === 0 ||
    parts.some((part) => part.length === 0 || part === '.' || part === '..')
  ) {
    throw new SetupError(`unsafe archive path ${JSON.stringify(rawName)}`);
  }
  if (normalized !== expectedRoot && !normalized.startsWith(`${expectedRoot}/`)) {
    throw new SetupError(`archive entry escapes expected top-level directory ${expectedRoot}`);
  }
  return {
    normalized,
    relative: normalized === expectedRoot ? '' : normalized.slice(expectedRoot.length + 1),
  };
}

function expectedEntries(executableName: string): Set<string> {
  return new Set(['', 'bin', `bin/${executableName}`, 'LICENSE', 'README.md']);
}

function validateExpectedEntry(
  relative: string,
  type: 'directory' | 'file',
  mode: number,
  executableName: string,
  format: ArchiveFormat,
): 0o644 | 0o755 {
  if (!expectedEntries(executableName).has(relative)) {
    throw new SetupError(`archive contains unexpected entry ${relative || '<root>'}`);
  }
  const expectedType = relative === '' || relative === 'bin' ? 'directory' : 'file';
  if (type !== expectedType) {
    throw new SetupError(`archive entry ${relative || '<root>'} has unexpected type ${type}`);
  }
  const expectedMode =
    expectedType === 'directory' || (relative === `bin/${executableName}` && format === 'tar.gz')
      ? 0o755
      : 0o644;
  if ((mode & 0o777) !== expectedMode) {
    throw new SetupError(
      `archive entry ${relative || '<root>'} has mode ${(mode & 0o777).toString(8)}, expected ${expectedMode.toString(8)}`,
    );
  }
  return expectedMode;
}

function finishManifest(
  entries: ArchiveEntry[],
  executableName: string,
): ArchiveManifest {
  const expected = expectedEntries(executableName);
  const actual = new Set(entries.map((entry) => entry.relativePath));
  if (actual.size !== expected.size || [...expected].some((name) => !actual.has(name))) {
    throw new SetupError('release archive does not contain the exact expected installation layout');
  }
  const binary = entries.find(
    (entry) => entry.relativePath === `bin/${executableName}`,
  )?.data;
  if (!binary || binary.length === 0) {
    throw new SetupError(`release archive is missing nonempty bin/${executableName}`);
  }
  return { entries, binary, binaryDigest: sha256Bytes(binary) };
}

export function decompressGzip(archive: Buffer): Buffer {
  if (archive.length > MAX_ARCHIVE_BYTES) {
    throw new SetupError(`release archive exceeds ${MAX_ARCHIVE_BYTES} bytes`);
  }
  if (archive.length < 18 || !archive.subarray(0, 3).equals(Buffer.from([0x1f, 0x8b, 0x08]))) {
    throw new SetupError('release archive is not a valid gzip stream');
  }
  if (archive[3] !== 0) {
    throw new SetupError('release archive gzip header contains unsupported optional fields');
  }
  if (archive.readUInt32LE(4) !== 0) {
    throw new SetupError('release archive gzip timestamp is not canonical');
  }
  const compressed = archive.subarray(10, archive.length - 8);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateRawSync(compressed, {
      info: true,
      maxOutputLength: MAX_EXPANDED_BYTES,
    }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (error) {
    throw new SetupError(`release archive gzip payload is invalid: ${errorMessage(error)}`, {
      cause: error,
    });
  }
  const output = result.buffer;
  if (result.engine.bytesWritten !== compressed.length) {
    throw new SetupError('release archive gzip stream contains trailing or concatenated data');
  }
  const expectedCRC = archive.readUInt32LE(archive.length - 8);
  const expectedSize = archive.readUInt32LE(archive.length - 4);
  if (crc32(output) !== expectedCRC) {
    throw new SetupError('release archive gzip CRC-32 does not match');
  }
  if (output.length % 0x1_0000_0000 !== expectedSize) {
    throw new SetupError('release archive gzip uncompressed size does not match');
  }
  return output;
}

export function parseTarGzArchive(
  archive: Buffer,
  expectedRoot: string,
  executableName: string,
): ArchiveManifest {
  const tar = decompressGzip(archive);
  if (tar.length === 0 || tar.length % TAR_BLOCK_SIZE !== 0) {
    throw new SetupError('release tar stream is empty or not block-aligned');
  }

  const entries: ArchiveEntry[] = [];
  const seen = new Set<string>();
  let offset = 0;
  let zeroBlocks = 0;

  while (offset < tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += TAR_BLOCK_SIZE;
      if (zeroBlocks >= 2) {
        if (!tar.subarray(offset).every((byte) => byte === 0)) {
          throw new SetupError('release tar stream contains data after its end marker');
        }
        break;
      }
      continue;
    }
    if (zeroBlocks > 0) {
      throw new SetupError('release tar stream contains an incomplete end marker');
    }
    if (entries.length >= MAX_ENTRIES) {
      throw new SetupError(`release tar stream exceeds ${MAX_ENTRIES} entries`);
    }
    validateChecksum(header);
    const magic = header.subarray(257, 263).toString('ascii');
    if (magic !== 'ustar\0' && magic !== 'ustar ') {
      throw new SetupError('release tar entry is not in ustar format');
    }
    const name = decodeString(header.subarray(0, 100), 'tar entry name');
    const prefix = decodeString(header.subarray(345, 500), 'tar entry prefix');
    const rawName = prefix ? `${prefix}/${name}` : name;
    const { normalized, relative } = safeArchivePath(rawName, expectedRoot);
    if (seen.has(normalized)) {
      throw new SetupError(`release tar stream contains duplicate entry ${normalized}`);
    }
    seen.add(normalized);

    const mode = parseOctal(header.subarray(100, 108), `mode for ${normalized}`);
    const uid = parseOctal(header.subarray(108, 116), `uid for ${normalized}`);
    const gid = parseOctal(header.subarray(116, 124), `gid for ${normalized}`);
    const size = parseOctal(header.subarray(124, 136), `size for ${normalized}`);
    const uname = decodeString(header.subarray(265, 297), `owner for ${normalized}`);
    const gname = decodeString(header.subarray(297, 329), `group for ${normalized}`);
    if (uid !== 0 || gid !== 0 || uname !== '' || gname !== '') {
      throw new SetupError(`release tar entry ${normalized} has non-canonical ownership`);
    }
    const typeByte = header[156] ?? 0;
    let type: 'file' | 'directory';
    if (typeByte === 0 || typeByte === 0x30) {
      type = 'file';
    } else if (typeByte === 0x35) {
      type = 'directory';
    } else {
      throw new SetupError(`release tar entry ${normalized} is a link or special file`);
    }
    if (type === 'directory' && size !== 0) {
      throw new SetupError(`release tar directory ${normalized} has a nonzero size`);
    }
    if (type === 'file' && size > MAX_FILE_BYTES) {
      throw new SetupError(`release tar file ${normalized} exceeds ${MAX_FILE_BYTES} bytes`);
    }
    const expectedMode = validateExpectedEntry(
      relative,
      type,
      mode,
      executableName,
      'tar.gz',
    );

    const dataOffset = offset + TAR_BLOCK_SIZE;
    const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    const nextOffset = dataOffset + paddedSize;
    if (nextOffset > tar.length) {
      throw new SetupError(`release tar entry ${normalized} is truncated`);
    }
    const data = type === 'file' ? Buffer.from(tar.subarray(dataOffset, dataOffset + size)) : undefined;
    entries.push({
      relativePath: relative,
      type,
      mode: expectedMode,
      ...(data ? { data } : {}),
    });
    offset = nextOffset;
  }

  if (zeroBlocks < 2) {
    throw new SetupError('release tar stream has no complete end marker');
  }
  return finishManifest(entries, executableName);
}

function openZip(archive: Buffer): Promise<ZipFile> {
  if (archive.length > MAX_ARCHIVE_BYTES) {
    throw new SetupError(`release archive exceeds ${MAX_ARCHIVE_BYTES} bytes`);
  }
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      archive,
      {
        autoClose: true,
        decodeStrings: true,
        lazyEntries: true,
        strictFileNames: true,
        validateEntrySizes: true,
      },
      (error, zip) => {
        if (error || !zip) {
          reject(new SetupError(`release zip archive is invalid: ${errorMessage(error)}`));
          return;
        }
        resolve(zip);
      },
    );
  });
}

function readZipEntry(zip: ZipFile, entry: Entry): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error || !stream) {
        reject(new SetupError(`could not read zip entry ${entry.fileName}: ${errorMessage(error)}`));
        return;
      }
      const chunks: Buffer[] = [];
      let length = 0;
      stream.on('data', (chunk: Buffer | string) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += bytes.length;
        if (length > entry.uncompressedSize || length > MAX_FILE_BYTES) {
          stream.destroy(new SetupError(`zip entry ${entry.fileName} exceeds its size bound`));
          return;
        }
        chunks.push(bytes);
      });
      stream.on('error', reject);
      stream.on('end', () => {
        if (length !== entry.uncompressedSize) {
          reject(
            new SetupError(
              `zip entry ${entry.fileName} size mismatch: expected ${entry.uncompressedSize}, received ${length}`,
            ),
          );
          return;
        }
        resolve(Buffer.concat(chunks, length));
      });
    });
  });
}

export async function parseZipArchive(
  archive: Buffer,
  expectedRoot: string,
  executableName: string,
): Promise<ArchiveManifest> {
  const zip = await openZip(archive);
  const entries: ArchiveEntry[] = [];
  const seen = new Set<string>();
  let expandedBytes = 0;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      zip.close();
      reject(error);
    };
    zip.on('error', fail);
    zip.on('end', () => {
      if (settled) return;
      settled = true;
      resolve();
    });
    zip.on('entry', (entry: Entry) => {
      void (async () => {
        if (entries.length >= MAX_ENTRIES) {
          throw new SetupError(`release zip archive exceeds ${MAX_ENTRIES} entries`);
        }
        if ((entry.generalPurposeBitFlag & 0x1) !== 0) {
          throw new SetupError(`release zip entry ${entry.fileName} is encrypted`);
        }
        if (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) {
          throw new SetupError(
            `release zip entry ${entry.fileName} uses unsupported compression method ${entry.compressionMethod}`,
          );
        }
        if (entry.uncompressedSize > MAX_FILE_BYTES) {
          throw new SetupError(`release zip entry ${entry.fileName} exceeds ${MAX_FILE_BYTES} bytes`);
        }
        expandedBytes += entry.uncompressedSize;
        if (expandedBytes > MAX_EXPANDED_BYTES) {
          throw new SetupError(`release zip archive exceeds ${MAX_EXPANDED_BYTES} expanded bytes`);
        }

        const { normalized, relative } = safeArchivePath(entry.fileName, expectedRoot);
        if (seen.has(normalized)) {
          throw new SetupError(`release zip archive contains duplicate entry ${normalized}`);
        }
        seen.add(normalized);
        const directory = entry.fileName.endsWith('/');
        const type = directory ? 'directory' : 'file';
        const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
        const fileType = unixMode & 0o170000;
        if (fileType !== 0 && fileType !== 0o100000 && fileType !== 0o040000) {
          throw new SetupError(`release zip entry ${normalized} is a link or special file`);
        }
        const expectedMode = validateExpectedEntry(
          relative,
          type,
          unixMode,
          executableName,
          'zip',
        );
        if (directory && entry.uncompressedSize !== 0) {
          throw new SetupError(`release zip directory ${normalized} has a nonzero size`);
        }
        const data = directory ? undefined : await readZipEntry(zip, entry);
        entries.push({
          relativePath: relative,
          type,
          mode: expectedMode,
          ...(data ? { data } : {}),
        });
        zip.readEntry();
      })().catch(fail);
    });
    zip.readEntry();
  });

  return finishManifest(entries, executableName);
}

export async function parseArchive(
  archive: Buffer,
  expectedRoot: string,
  executableName: string,
  format: ArchiveFormat,
): Promise<ArchiveManifest> {
  return format === 'tar.gz'
    ? parseTarGzArchive(archive, expectedRoot, executableName)
    : await parseZipArchive(archive, expectedRoot, executableName);
}

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await lstat(candidate);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function writeManifest(root: string, archive: Buffer, manifest: ArchiveManifest): Promise<void> {
  for (const entry of manifest.entries) {
    const destination = entry.relativePath ? path.join(root, entry.relativePath) : root;
    if (entry.type === 'directory') {
      await mkdir(destination, { recursive: true, mode: entry.mode });
      await chmod(destination, entry.mode);
      continue;
    }
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    await writeFile(destination, entry.data as Buffer, {
      flag: 'wx',
      mode: entry.mode,
    });
    await chmod(destination, entry.mode);
  }
  await writeFile(path.join(root, CACHED_ARCHIVE_NAME), archive, {
    flag: 'wx',
    mode: 0o600,
  });
}

export async function publishArchive(
  archive: Buffer,
  expectedRoot: string,
  finalRoot: string,
  executableName: string,
  format: ArchiveFormat,
): Promise<'published' | 'raced'> {
  const manifest = await parseArchive(archive, expectedRoot, executableName, format);
  const parent = path.dirname(finalRoot);
  await mkdir(parent, { recursive: true, mode: 0o755 });
  const staging = path.join(parent, `.stage-${process.pid}-${randomUUID()}`);
  await mkdir(staging, { mode: 0o700 });
  try {
    await writeManifest(staging, archive, manifest);
    try {
      await rename(staging, finalRoot);
      return 'published';
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST' || code === 'ENOTEMPTY') {
        return 'raced';
      }
      throw error;
    }
  } finally {
    if (await pathExists(staging)) {
      await rm(staging, { recursive: true, force: true });
    }
  }
}

async function collectTree(root: string, relative = ''): Promise<Map<string, Stats>> {
  const result = new Map<string, Stats>();
  const directory = relative ? path.join(root, relative) : root;
  for (const name of await readdir(directory)) {
    if (relative.length === 0 && name === CACHED_ARCHIVE_NAME) {
      continue;
    }
    const childRelative = relative ? `${relative}/${name}` : name;
    const child = path.join(root, childRelative);
    const info = await lstat(child);
    result.set(childRelative, info);
    if (info.isDirectory()) {
      for (const [nestedPath, nestedInfo] of await collectTree(root, childRelative)) {
        result.set(nestedPath, nestedInfo);
      }
    }
  }
  return result;
}

export async function verifyCachedInstallation(
  finalRoot: string,
  expectedRoot: string,
  expectedArchiveSize: number,
  expectedArchiveDigest: string,
  executableName: string,
  format: ArchiveFormat,
): Promise<{ executablePath: string; binaryDigest: string }> {
  const rootInfo = await lstat(finalRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new SetupError('cached installation root is not a regular directory');
  }
  if (process.platform !== 'win32' && (rootInfo.mode & 0o777) !== 0o755) {
    throw new SetupError('cached installation root is not a mode-755 directory');
  }
  const archivePath = path.join(finalRoot, CACHED_ARCHIVE_NAME);
  const archiveInfo = await lstat(archivePath);
  if (!archiveInfo.isFile() || archiveInfo.isSymbolicLink()) {
    throw new SetupError('cached release archive is not a regular file');
  }
  if (archiveInfo.size !== expectedArchiveSize) {
    throw new SetupError(
      `cached release archive size mismatch: expected ${expectedArchiveSize}, found ${archiveInfo.size}`,
    );
  }
  const archive = await readFile(archivePath);
  const actualArchiveDigest = sha256Bytes(archive);
  if (actualArchiveDigest !== expectedArchiveDigest) {
    throw new SetupError(
      `cached release archive SHA-256 mismatch: expected ${expectedArchiveDigest}, found ${actualArchiveDigest}`,
    );
  }
  const manifest = await parseArchive(archive, expectedRoot, executableName, format);
  const expected = new Map(
    manifest.entries
      .filter((entry) => entry.relativePath.length > 0)
      .map((entry) => [entry.relativePath, entry]),
  );
  const actual = await collectTree(finalRoot);
  if (actual.size !== expected.size || [...actual.keys()].some((name) => !expected.has(name))) {
    throw new SetupError('cached installation layout differs from the authenticated archive');
  }
  for (const [relative, entry] of expected) {
    const info = actual.get(relative);
    if (!info) {
      throw new SetupError(`cached installation is missing ${relative}`);
    }
    if (process.platform !== 'win32' && (info.mode & 0o777) !== entry.mode) {
      throw new SetupError(
        `cached installation mode mismatch for ${relative}: expected ${entry.mode.toString(8)}, found ${(info.mode & 0o777).toString(8)}`,
      );
    }
    if (entry.type === 'directory') {
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw new SetupError(`cached installation ${relative} is not a directory`);
      }
      continue;
    }
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new SetupError(`cached installation ${relative} is not a regular file`);
    }
    const data = await readFile(path.join(finalRoot, relative));
    if (!(entry.data as Buffer).equals(data)) {
      throw new SetupError(`cached installation content mismatch for ${relative}`);
    }
  }
  return {
    executablePath: path.join(finalRoot, 'bin', executableName),
    binaryDigest: manifest.binaryDigest,
  };
}

export async function exists(candidate: string): Promise<boolean> {
  return await pathExists(candidate);
}
