import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { SetupError, errorMessage } from './errors.js';

const execFileAsync = promisify(execFile);

export type InstallationRunner = (
  executablePath: string,
  expectedVersion: string,
  expectedTarget: string,
) => Promise<void>;

async function runCommand(
  executablePath: string,
  arguments_: string[],
): Promise<{ stdout: string; stderr: string }> {
  const environment: NodeJS.ProcessEnv = {
    LANG: 'C',
    LC_ALL: 'C',
  };
  for (const key of ['SystemRoot', 'SYSTEMROOT', 'WINDIR']) {
    if (process.env[key]) {
      environment[key] = process.env[key];
    }
  }
  try {
    return await execFileAsync(executablePath, arguments_, {
      encoding: 'utf8',
      env: environment,
      timeout: 10_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    throw new SetupError(
      `installed ghr ${arguments_.join(' ')} check failed: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

function validateOutput(
  result: { stdout: string; stderr: string },
  expected: string,
  label: string,
): void {
  if (result.stderr !== '') {
    throw new SetupError(`installed ghr ${label} check wrote unexpected stderr`);
  }
  if (result.stdout !== `${expected}\n` && result.stdout !== `${expected}\r\n`) {
    throw new SetupError(
      `installed ghr reported ${JSON.stringify(result.stdout)} instead of ${JSON.stringify(expected)} for ${label}`,
    );
  }
}

export const verifyInstallation: InstallationRunner = async (
  executablePath,
  expectedVersion,
  expectedTarget,
) => {
  validateOutput(
    await runCommand(executablePath, ['version']),
    expectedVersion,
    'version',
  );
  validateOutput(
    await runCommand(executablePath, ['version', '--target']),
    expectedTarget,
    'target',
  );
};
