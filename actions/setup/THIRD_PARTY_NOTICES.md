# Third-party notices for `actions/setup`

The checked-in JavaScript bundles include the pinned dependencies and
transitive versions recorded in `package-lock.json`. Complete license texts
emitted by the bundler are committed as:

- `dist/main/licenses.txt`
- `dist/post/licenses.txt`

Direct runtime dependencies:

| Package | License |
| --- | --- |
| `@actions/core` | MIT |
| `@sigstore/bundle` | Apache-2.0 |
| `@sigstore/protobuf-specs` | Apache-2.0 |
| `@sigstore/tuf` | Apache-2.0 |
| `@sigstore/verify` | Apache-2.0 |
| `semver` | ISC |
| `undici` | MIT |
| `yauzl` | MIT |

The setup action adapts the trust and cache design of
[`cataggar/debz/actions/setup`](https://github.com/cataggar/debz/tree/main/actions/setup),
which is licensed under Apache-2.0.
