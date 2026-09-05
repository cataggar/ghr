import { SemVer } from 'semver';

import { SetupError } from './errors.js';

const EXACT_SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export interface ResolvedVersion {
  version: string;
  tag: string;
  source: 'input' | 'action-ref';
}

function parseVersion(value: string, label: string, requirePrefix: boolean): ResolvedVersion {
  if (value !== value.trim() || value.length === 0) {
    throw new SetupError(`${label} must be an exact SemVer without surrounding whitespace`);
  }
  if (value.length > 128) {
    throw new SetupError(`${label} exceeds the 128-character limit`);
  }
  const hasPrefix = value.startsWith('v');
  if (requirePrefix && !hasPrefix) {
    throw new SetupError(`${label} must be an exact v-prefixed SemVer tag`);
  }
  const version = hasPrefix ? value.slice(1) : value;
  if (!EXACT_SEMVER.test(version)) {
    throw new SetupError(
      `${label} must be an exact SemVer such as v0.8.0 or v0.8.0-rc.1; ranges and "latest" are not allowed`,
    );
  }
  try {
    new SemVer(version, { loose: false });
  } catch (error) {
    throw new SetupError(`${label} is not a valid exact SemVer`, { cause: error });
  }
  return { version, tag: `v${version}`, source: requirePrefix ? 'action-ref' : 'input' };
}

export function resolveVersion(explicitVersion: string, actionRef: string): ResolvedVersion {
  if (explicitVersion.length > 0) {
    return parseVersion(explicitVersion, 'ghr-version', false);
  }
  if (actionRef.length === 0) {
    throw new SetupError(
      'ghr-version is required when the action ref is unavailable; commit- and branch-pinned actions must set it explicitly',
    );
  }
  return parseVersion(actionRef, 'github.action_ref', true);
}
