import { SetupError } from './errors.js';

export type AssetTarget =
  | 'linux-musl-x64'
  | 'linux-musl-arm64'
  | 'macos-x64'
  | 'macos-arm64'
  | 'windows-x64'
  | 'windows-arm64';

export type ArchiveFormat = 'tar.gz' | 'zip';

export interface Platform {
  target: AssetTarget;
  cliTarget: string;
  archiveFormat: ArchiveFormat;
  executableName: 'ghr' | 'ghr.exe';
}

interface Mapping {
  target: AssetTarget;
  cliTarget: string;
  processPlatform: NodeJS.Platform;
  processArch: NodeJS.Architecture;
  archiveFormat: ArchiveFormat;
  executableName: 'ghr' | 'ghr.exe';
}

const MAPPINGS: Record<string, Mapping> = {
  'Linux/X64': {
    target: 'linux-musl-x64',
    cliTarget: 'linux-x86_64-musl',
    processPlatform: 'linux',
    processArch: 'x64',
    archiveFormat: 'tar.gz',
    executableName: 'ghr',
  },
  'Linux/ARM64': {
    target: 'linux-musl-arm64',
    cliTarget: 'linux-aarch64-musl',
    processPlatform: 'linux',
    processArch: 'arm64',
    archiveFormat: 'tar.gz',
    executableName: 'ghr',
  },
  'macOS/X64': {
    target: 'macos-x64',
    cliTarget: 'macos-x86_64-none',
    processPlatform: 'darwin',
    processArch: 'x64',
    archiveFormat: 'tar.gz',
    executableName: 'ghr',
  },
  'macOS/ARM64': {
    target: 'macos-arm64',
    cliTarget: 'macos-aarch64-none',
    processPlatform: 'darwin',
    processArch: 'arm64',
    archiveFormat: 'tar.gz',
    executableName: 'ghr',
  },
  'Windows/X64': {
    target: 'windows-x64',
    cliTarget: 'windows-x86_64-gnu',
    processPlatform: 'win32',
    processArch: 'x64',
    archiveFormat: 'zip',
    executableName: 'ghr.exe',
  },
  'Windows/ARM64': {
    target: 'windows-arm64',
    cliTarget: 'windows-aarch64-gnu',
    processPlatform: 'win32',
    processArch: 'arm64',
    archiveFormat: 'zip',
    executableName: 'ghr.exe',
  },
};

export function normalizePlatform(
  runnerOS: string,
  runnerArch: string,
  processPlatform = process.platform,
  processArch = process.arch,
): Platform {
  const key = `${runnerOS}/${runnerArch}`;
  const mapping = MAPPINGS[key];
  if (!mapping) {
    throw new SetupError(
      `unsupported runner target: RUNNER_OS=${runnerOS || '<unset>'}, RUNNER_ARCH=${runnerArch || '<unset>'}; supported targets are Linux, macOS, and Windows on X64 or ARM64`,
    );
  }
  if (
    processPlatform !== mapping.processPlatform ||
    processArch !== mapping.processArch
  ) {
    throw new SetupError(
      `runner target mismatch: RUNNER_OS=${runnerOS}, RUNNER_ARCH=${runnerArch}, process.platform=${processPlatform}, process.arch=${processArch}`,
    );
  }
  return {
    target: mapping.target,
    cliTarget: mapping.cliTarget,
    archiveFormat: mapping.archiveFormat,
    executableName: mapping.executableName,
  };
}
