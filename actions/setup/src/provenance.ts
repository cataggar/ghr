import { bundleFromJSON } from '@sigstore/bundle';
import type { TrustedRoot } from '@sigstore/protobuf-specs';
import { DEFAULT_MIRROR_URL, getTrustedRoot } from '@sigstore/tuf';
import { Verifier, toSignedEntity, toTrustMaterial } from '@sigstore/verify';

import { SetupError, errorMessage } from './errors.js';
import {
  RELEASE_OWNER_ID,
  RELEASE_REPOSITORY_ID,
  RELEASE_REPOSITORY_URL,
  RELEASE_WORKFLOW_PATH,
} from './github.js';

const IN_TOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const SLSA_PROVENANCE_TYPE = 'https://slsa.dev/provenance/v1';
const GITHUB_WORKFLOW_BUILD_TYPE = 'https://actions.github.io/buildtypes/workflow/v1';
const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const MAX_PAYLOAD_BYTES = 1024 * 1024;

export interface ProvenanceExpectation {
  tag: string;
  assetName: string;
  digest: string;
  commit: string;
}

export type TrustedRootLoader = (cachePath: string) => Promise<TrustedRoot>;
export type CryptographicBundleVerifier = (
  bundle: unknown,
  trustedRoot: TrustedRoot,
  expected: ProvenanceExpectation,
) => void;

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SetupError(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new SetupError(`${label} is not an array`);
  }
  return value;
}

function exactString(value: unknown, expected: string, label: string): void {
  if (value !== expected) {
    throw new SetupError(`${label} does not match the required value`);
  }
}

function decodeBase64(value: unknown, label: string): Buffer {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new SetupError(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new SetupError(`${label} is not canonical base64`);
  }
  return decoded;
}

export function certificateIdentity(tag: string): string {
  return `${RELEASE_REPOSITORY_URL}/${RELEASE_WORKFLOW_PATH}@refs/tags/${tag}`;
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function certificateIdentityPattern(tag: string): RegExp {
  return new RegExp(`^${escapeRegularExpression(certificateIdentity(tag))}$`);
}

export function validateProvenanceStatement(
  rawBundle: unknown,
  expected: ProvenanceExpectation,
): void {
  const bundle = record(rawBundle, 'Sigstore bundle');
  const envelope = record(bundle.dsseEnvelope, 'Sigstore DSSE envelope');
  exactString(envelope.payloadType, 'application/vnd.in-toto+json', 'DSSE payload type');
  const payloadBytes = decodeBase64(envelope.payload, 'DSSE payload');
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    throw new SetupError(`attestation payload exceeds ${MAX_PAYLOAD_BYTES} bytes`);
  }

  let statementValue: unknown;
  try {
    statementValue = JSON.parse(payloadBytes.toString('utf8'));
  } catch (error) {
    throw new SetupError('attestation payload is not valid JSON', { cause: error });
  }
  const statement = record(statementValue, 'attestation statement');
  exactString(statement._type, IN_TOTO_STATEMENT_TYPE, 'in-toto statement type');
  exactString(statement.predicateType, SLSA_PROVENANCE_TYPE, 'predicate type');

  const matchingSubjects = array(statement.subject, 'attestation subjects').filter((value) => {
    const subject = record(value, 'attestation subject');
    const digest = record(subject.digest, 'attestation subject digest');
    return subject.name === expected.assetName && digest.sha256 === expected.digest;
  });
  if (matchingSubjects.length === 0) {
    throw new SetupError(
      `attestation has no subject matching ${expected.assetName} and sha256:${expected.digest}`,
    );
  }

  const predicate = record(statement.predicate, 'attestation predicate');
  const buildDefinition = record(predicate.buildDefinition, 'attestation build definition');
  exactString(
    buildDefinition.buildType,
    GITHUB_WORKFLOW_BUILD_TYPE,
    'attestation build type',
  );
  const externalParameters = record(
    buildDefinition.externalParameters,
    'attestation external parameters',
  );
  const workflow = record(externalParameters.workflow, 'attestation workflow parameters');
  const ref = `refs/tags/${expected.tag}`;
  exactString(workflow.repository, RELEASE_REPOSITORY_URL, 'attestation repository');
  exactString(workflow.path, RELEASE_WORKFLOW_PATH, 'attestation workflow path');
  exactString(workflow.ref, ref, 'attestation workflow ref');

  const internalParameters = record(
    buildDefinition.internalParameters,
    'attestation internal parameters',
  );
  const github = record(internalParameters.github, 'attestation GitHub parameters');
  exactString(
    github.repository_id,
    String(RELEASE_REPOSITORY_ID),
    'attestation repository ID',
  );
  exactString(github.repository_owner_id, RELEASE_OWNER_ID, 'attestation owner ID');
  exactString(github.event_name, 'push', 'attestation event');
  exactString(github.runner_environment, 'github-hosted', 'attestation runner environment');

  const dependencyURI = `git+${RELEASE_REPOSITORY_URL}@${ref}`;
  const dependencies = array(
    buildDefinition.resolvedDependencies,
    'attestation resolved dependencies',
  );
  const matchingDependencies = dependencies.filter((value) => {
    const dependency = record(value, 'attestation resolved dependency');
    const digest = record(dependency.digest, 'attestation dependency digest');
    return dependency.uri === dependencyURI && digest.gitCommit === expected.commit;
  });
  if (matchingDependencies.length === 0) {
    throw new SetupError(
      `attestation does not resolve ${expected.tag} to commit ${expected.commit}`,
    );
  }

  const runDetails = record(predicate.runDetails, 'attestation run details');
  const builder = record(runDetails.builder, 'attestation builder');
  exactString(builder.id, certificateIdentity(expected.tag), 'attestation builder identity');
}

export function verifySigstoreBundle(
  rawBundle: unknown,
  trustedRoot: TrustedRoot,
  expected: ProvenanceExpectation,
): void {
  const bundle = bundleFromJSON(rawBundle);
  const verifier = new Verifier(toTrustMaterial(trustedRoot), {
    tlogThreshold: 1,
    ctlogThreshold: 1,
  });
  verifier.verify(toSignedEntity(bundle), {
    subjectAlternativeName: certificateIdentityPattern(expected.tag),
    extensions: { issuer: GITHUB_OIDC_ISSUER },
    oids: [
      {
        oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 2] },
        value: Buffer.from('push'),
      },
      {
        oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 3] },
        value: Buffer.from(expected.commit),
      },
      {
        oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 5] },
        value: Buffer.from('cataggar/ghr'),
      },
      {
        oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 6] },
        value: Buffer.from(`refs/tags/${expected.tag}`),
      },
    ],
  });
}

async function defaultTrustedRootLoader(cachePath: string): Promise<TrustedRoot> {
  return await getTrustedRoot({
    cachePath,
    mirrorURL: DEFAULT_MIRROR_URL,
    forceInit: true,
    timeout: 10_000,
    retry: {
      retries: 2,
      factor: 2,
      minTimeout: 250,
      maxTimeout: 1000,
      randomize: false,
    },
  });
}

export async function verifyProvenance(
  bundles: unknown[],
  expected: ProvenanceExpectation,
  tufCachePath: string,
  loadTrustedRoot: TrustedRootLoader = defaultTrustedRootLoader,
  verifyBundle: CryptographicBundleVerifier = verifySigstoreBundle,
): Promise<void> {
  let trustedRoot: TrustedRoot;
  try {
    trustedRoot = await loadTrustedRoot(tufCachePath);
  } catch (error) {
    throw new SetupError(
      `could not load the Sigstore trusted root through TUF: ${errorMessage(error)}; provide sha256 only if you have an independent trusted digest`,
      { cause: error },
    );
  }

  const failures: string[] = [];
  for (const [index, bundle] of bundles.entries()) {
    try {
      verifyBundle(bundle, trustedRoot, expected);
      validateProvenanceStatement(bundle, expected);
      return;
    } catch (error) {
      failures.push(`bundle ${index + 1}: ${errorMessage(error).slice(0, 240)}`);
    }
  }
  throw new SetupError(
    `no cryptographically valid GitHub release provenance matched the requested asset (${failures.slice(0, 3).join('; ')})`,
  );
}
