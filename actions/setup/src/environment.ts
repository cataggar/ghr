import { Agent, setGlobalDispatcher } from 'undici';

const AMBIENT_CONFIGURATION_KEYS = [
  'ALL_PROXY',
  'FTP_PROXY',
  'GH_ENTERPRISE_TOKEN',
  'GH_HOST',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'GIT_ASKPASS',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_NOSYSTEM',
  'GIT_SSH',
  'GIT_SSH_COMMAND',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_USE_ENV_PROXY',
  'NO_PROXY',
  'NPM_CONFIG_USERCONFIG',
  'all_proxy',
  'ftp_proxy',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  'npm_config_userconfig',
] as const;

export function clearAmbientConfiguration(environment: NodeJS.ProcessEnv = process.env): void {
  for (const key of AMBIENT_CONFIGURATION_KEYS) {
    delete environment[key];
  }
}

export function configureDirectNetwork(environment: NodeJS.ProcessEnv = process.env): void {
  clearAmbientConfiguration(environment);
  setGlobalDispatcher(
    new Agent({
      connect: { timeout: 10_000 },
      headersTimeout: 15_000,
      bodyTimeout: 15_000,
    }),
  );
}
