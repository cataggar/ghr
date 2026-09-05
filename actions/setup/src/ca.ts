import { createHash, randomUUID } from 'node:crypto';
import {
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import { lt } from 'semver';

import { SetupError } from './errors.js';

const MAX_ROOT_CERTIFICATES = 256;
const MAX_CA_BUNDLE_SIZE = 4 * 1024 * 1024;

export const LINUX_CA_BUNDLE_PATHS = [
  '/etc/ssl/certs/ca-certificates.crt',
  '/etc/pki/tls/certs/ca-bundle.crt',
  '/etc/ssl/ca-bundle.pem',
  '/etc/pki/tls/cacert.pem',
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
  '/etc/ssl/cert.pem',
] as const;

export interface CaTrustIO {
  exportVariable(name: string, value: string): void;
  info(message: string): void;
}

export interface CaTrustOptions {
  rootCertificates?: readonly string[];
  systemBundlePaths?: readonly string[];
}

function errorCode(error: unknown): string | undefined {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return error.code;
  }
  return undefined;
}

async function isNonemptyFile(filePath: string): Promise<boolean> {
  try {
    const metadata = await stat(filePath);
    return metadata.isFile() && metadata.size > 0;
  } catch (error) {
    if (errorCode(error) === 'ENOENT' || errorCode(error) === 'ENOTDIR') {
      return false;
    }
    throw error;
  }
}

function serializeRootCertificates(certificates: readonly string[]): Buffer {
  if (
    certificates.length === 0 ||
    certificates.length > MAX_ROOT_CERTIFICATES
  ) {
    throw new SetupError(
      `Node TLS root set must contain between 1 and ${MAX_ROOT_CERTIFICATES} certificates`,
    );
  }

  for (const certificate of certificates) {
    if (
      certificate.includes('\0') ||
      !certificate.startsWith('-----BEGIN CERTIFICATE-----\n') ||
      !certificate.endsWith('\n-----END CERTIFICATE-----')
    ) {
      throw new SetupError('Node TLS root set contains a malformed PEM certificate');
    }
  }

  const bundle = Buffer.from(`${certificates.join('\n')}\n`, 'ascii');
  if (bundle.length === 0 || bundle.length > MAX_CA_BUNDLE_SIZE) {
    throw new SetupError(
      `Node TLS root bundle exceeds the ${MAX_CA_BUNDLE_SIZE}-byte limit`,
    );
  }
  return bundle;
}

async function writeBundle(
  runnerTemp: string,
  certificates: readonly string[],
): Promise<string> {
  const bundle = serializeRootCertificates(certificates);
  const digest = createHash('sha256').update(bundle).digest('hex');
  const directory = path.join(runnerTemp, 'ghr-setup-ca');
  const bundlePath = path.join(directory, `node24-roots-${digest}.pem`);
  const temporaryPath = path.join(
    directory,
    `.node24-roots-${process.pid}-${randomUUID()}.tmp`,
  );

  await mkdir(directory, { recursive: true, mode: 0o755 });
  try {
    await writeFile(temporaryPath, bundle, { flag: 'wx', mode: 0o644 });
    try {
      await rename(temporaryPath, bundlePath);
    } catch (error) {
      if (!['EEXIST', 'EPERM'].includes(errorCode(error) ?? '')) {
        throw error;
      }
      const existing = await readFile(bundlePath);
      if (!existing.equals(bundle)) {
        throw new SetupError(
          `existing Node TLS root bundle does not match its content digest: ${bundlePath}`,
        );
      }
    }
  } finally {
    await rm(temporaryPath, { force: true });
  }
  return bundlePath;
}

export async function configureCaTrust(
  runnerTemp: string,
  processPlatform: NodeJS.Platform,
  version: string,
  configuredBundlePath: string,
  io: CaTrustIO,
  options: CaTrustOptions = {},
): Promise<void> {
  if (processPlatform !== 'linux') {
    return;
  }

  const systemBundlePaths =
    options.systemBundlePaths ?? LINUX_CA_BUNDLE_PATHS;
  if (systemBundlePaths.length === 0) {
    throw new SetupError('Linux CA bundle path list must not be empty');
  }
  let bundlePath: string;
  if (configuredBundlePath.length > 0) {
    if (
      !path.isAbsolute(configuredBundlePath) ||
      !(await isNonemptyFile(configuredBundlePath))
    ) {
      throw new SetupError(
        'SSL_CERT_FILE must name an absolute, nonempty CA bundle file',
      );
    }
    bundlePath = path.resolve(configuredBundlePath);
  } else {
    for (const systemBundlePath of systemBundlePaths) {
      if (await isNonemptyFile(systemBundlePath)) {
        return;
      }
    }
    bundlePath = await writeBundle(
      runnerTemp,
      options.rootCertificates ?? rootCertificates,
    );
  }
  io.exportVariable('SSL_CERT_FILE', bundlePath);
  const trustSource =
    configuredBundlePath.length > 0
      ? 'configured TLS roots'
      : 'Node 24 TLS roots';

  // v0.8.0 and newer honor SSL_CERT_FILE directly. The currently published
  // prerelease needs a conventional Zig CA path while it bootstraps v0.8.0.
  if (!lt(version, '0.8.0')) {
    io.info(`Provisioned ${trustSource} for static ghr at ${bundlePath}`);
    return;
  }

  const fallbackPath = systemBundlePaths[0];

  try {
    await mkdir(path.dirname(fallbackPath), { recursive: true, mode: 0o755 });
    await symlink(bundlePath, fallbackPath);
  } catch (error) {
    if (
      errorCode(error) !== 'EEXIST' ||
      !(await isNonemptyFile(fallbackPath))
    ) {
      throw new SetupError(
        `no system CA bundle is available and the action could not create ${fallbackPath}; run the Linux job container as root or install ca-certificates`,
        { cause: error },
      );
    }
  }

  io.info(
    `Provisioned ${trustSource} for legacy static ghr at ${fallbackPath}`,
  );
}
