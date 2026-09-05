import { gzipSync } from 'node:zlib';

export interface TestTarEntry {
  name: string;
  type: '0' | '2' | '3' | '5';
  data?: Buffer;
  mode?: number;
}

function writeString(header: Buffer, offset: number, length: number, value: string): void {
  const bytes = Buffer.from(value, 'ascii');
  if (bytes.length > length) {
    throw new Error(`test tar field is too long: ${value}`);
  }
  bytes.copy(header, offset);
}

function writeOctal(header: Buffer, offset: number, length: number, value: number): void {
  const text = value.toString(8).padStart(length - 1, '0');
  writeString(header, offset, length, `${text}\0`);
}

function tarHeader(entry: TestTarEntry): Buffer {
  const header = Buffer.alloc(512);
  const directory = entry.type === '5';
  const data = directory ? Buffer.alloc(0) : (entry.data ?? Buffer.alloc(0));
  writeString(header, 0, 100, entry.name + (directory && !entry.name.endsWith('/') ? '/' : ''));
  writeOctal(header, 100, 8, entry.mode ?? (directory ? 0o755 : 0o644));
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, data.length);
  writeOctal(header, 136, 12, 1_700_000_000);
  header.fill(0x20, 148, 156);
  writeString(header, 156, 1, entry.type);
  writeString(header, 257, 6, 'ustar\0');
  writeString(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

export function makeTar(entries: TestTarEntry[]): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.type === '5' ? Buffer.alloc(0) : (entry.data ?? Buffer.alloc(0));
    chunks.push(tarHeader(entry), data);
    const padding = (512 - (data.length % 512)) % 512;
    if (padding > 0) {
      chunks.push(Buffer.alloc(padding));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function makeTarArchive(
  root = 'ghr-1.2.3-linux-musl-x64',
  overrides: TestTarEntry[] = [],
): Buffer {
  const entries: TestTarEntry[] = [
    { name: root, type: '5' },
    { name: `${root}/bin`, type: '5' },
    {
      name: `${root}/bin/ghr`,
      type: '0',
      mode: 0o755,
      data: Buffer.from('test ghr executable\n'),
    },
    { name: `${root}/LICENSE`, type: '0', data: Buffer.from('license\n') },
    { name: `${root}/README.md`, type: '0', data: Buffer.from('readme\n') },
    ...overrides,
  ];
  return gzipSync(makeTar(entries), { level: 9 });
}

interface ZipEntry {
  name: string;
  mode: number;
  data: Buffer;
  directory?: boolean;
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

export function makeZip(entries: ZipEntry[]): Buffer {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const crc = crc32(entry.data);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(entry.data.length, 18);
    localHeader.writeUInt32LE(entry.data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    local.push(localHeader, name, entry.data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE((3 << 8) | 20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(entry.data.length, 20);
    centralHeader.writeUInt32LE(entry.data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt32LE(
      (entry.mode << 16) | (entry.directory ? 0x10 : 0),
      38,
    );
    centralHeader.writeUInt32LE(offset, 42);
    central.push(centralHeader, name);
    offset += localHeader.length + name.length + entry.data.length;
  }
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, centralBytes, end]);
}

export function makeZipArchive(
  root = 'ghr-1.2.3-windows-x64',
  extra: ZipEntry[] = [],
): Buffer {
  return makeZip([
    { name: `${root}/`, mode: 0o755, data: Buffer.alloc(0), directory: true },
    { name: `${root}/bin/`, mode: 0o755, data: Buffer.alloc(0), directory: true },
    {
      name: `${root}/bin/ghr.exe`,
      mode: 0o644,
      data: Buffer.from('test ghr executable\n'),
    },
    { name: `${root}/LICENSE`, mode: 0o644, data: Buffer.from('license\n') },
    { name: `${root}/README.md`, mode: 0o644, data: Buffer.from('readme\n') },
    ...extra,
  ]);
}

export function releaseMetadata(
  digest: string,
  size: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    tag_name: 'v1.2.3',
    draft: false,
    prerelease: false,
    assets: [
      {
        id: 123,
        name: 'ghr-1.2.3-linux-musl-x64.tar.gz',
        state: 'uploaded',
        size,
        digest: `sha256:${digest}`,
        url: 'https://api.github.com/repos/cataggar/ghr/releases/assets/123',
      },
    ],
    ...overrides,
  };
}
