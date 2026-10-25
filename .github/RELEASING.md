# Experiential fork releases

GitHub Actions `ci.yml` builds and tests pull requests and main without publishing.
A protected `exp-v<version>` tag reachable from main publishes the tested
`exp-mitmproxy-rs` distributions through the `pypi` environment.
The tag must equal the Python package version prefixed with `exp-v`.
Manual workflow runs are build-only.

Configure the existing PyPI project with a GitHub trusted publisher:
owner `experientiallabs`, repository `mitmproxy_rs`, workflow `ci.yml`, environment `pypi`.
Only the publish job receives `id-token: write`. It uploads build artifacts
without checking out or executing package source. Duplicate filenames fail the
upload so a retry cannot silently combine files from different builds.
Protect `exp-v*` tag creation, updates, and deletion, and restrict the `pypi`
environment to those protected tags before creating a release tag.

## Upstream reference

# Publishing the Capture native package

This fork publishes `exp-mitmproxy-rs`. Its Python import remains `mitmproxy_rs`.
The original `mitmproxy_macos==0.12.11` package supplies the signed macOS app and
Network Extension. The release builds neither of those signed components.

Configure a pending trusted publisher at <https://pypi.org/manage/account/publishing/>:

- Project: `exp-mitmproxy-rs`
- Owner: `experientiallabs`
- Repository: `mitmproxy_rs`
- Workflow: `ci.yml`
- Environment: `pypi`

The GitHub repository needs an environment named `pypi`. No long-lived API token
is needed. The workflow publishes only `exp-v*` tags whose version matches
`mitmproxy-rs/pyproject.toml`, after every test and wheel build passes. Pull requests
and branch pushes cannot publish. PyPI receives the artifacts from that same run,
with publishing attestations.

For version `0.12.11.post1`, tag the intended tested commit and push that tag:

```sh
git tag exp-v0.12.11.post1 <commit>
git push experiential exp-v0.12.11.post1
```

Verify all four platform wheels and the source archive appear on PyPI before
publishing the dependent `exp-mitmproxy` package. Never replace a published version;
use a new post-release version for changes.
