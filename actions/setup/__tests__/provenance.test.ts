import assert from 'node:assert/strict';
import test from 'node:test';

import {
  certificateIdentity,
  certificateIdentityPattern,
  validateProvenanceStatement,
  verifyProvenance,
  type ProvenanceExpectation,
} from '../src/provenance.js';

const expected: ProvenanceExpectation = {
  tag: 'v1.2.3',
  assetName: 'ghr-1.2.3-linux-musl-x64.tar.gz',
  digest: 'a'.repeat(64),
  commit: 'b'.repeat(40),
};

function statement(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: expected.assetName, digest: { sha256: expected.digest } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://actions.github.io/buildtypes/workflow/v1',
        externalParameters: {
          workflow: {
            ref: `refs/tags/${expected.tag}`,
            repository: 'https://github.com/cataggar/ghr',
            path: '.github/workflows/release.yml',
          },
        },
        internalParameters: {
          github: {
            event_name: 'push',
            repository_id: '1209370122',
            repository_owner_id: '87583576',
            runner_environment: 'github-hosted',
          },
        },
        resolvedDependencies: [
          {
            uri: `git+https://github.com/cataggar/ghr@refs/tags/${expected.tag}`,
            digest: { gitCommit: expected.commit },
          },
        ],
      },
      runDetails: { builder: { id: certificateIdentity(expected.tag) } },
    },
    ...overrides,
  };
}

function bundle(value: Record<string, unknown>): Record<string, unknown> {
  return {
    dsseEnvelope: {
      payloadType: 'application/vnd.in-toto+json',
      payload: Buffer.from(JSON.stringify(value)).toString('base64'),
    },
  };
}

test('provenance statement binds exact repository, workflow, tag, commit, and subject', () => {
  validateProvenanceStatement(bundle(statement()), expected);
  const wrongSubject = statement({
    subject: [{ name: expected.assetName, digest: { sha256: '0'.repeat(64) } }],
  });
  assert.throws(
    () => validateProvenanceStatement(bundle(wrongSubject), expected),
    /no subject matching/,
  );
});

test('certificate identity pattern is exact and escaped', () => {
  const identity = certificateIdentity('v1.2.3+build.1');
  const pattern = certificateIdentityPattern('v1.2.3+build.1');
  assert.match(identity, pattern);
  assert.doesNotMatch(identity.replace('release.yml', 'releaseXyml'), pattern);
  assert.doesNotMatch(`prefix-${identity}`, pattern);
});

test('TUF failure is fail-closed and points to trusted SHA mode', async () => {
  await assert.rejects(
    verifyProvenance(
      [bundle(statement())],
      expected,
      '/unused',
      async () => {
        throw new Error('offline');
      },
    ),
    /through TUF.*provide sha256/,
  );
});
