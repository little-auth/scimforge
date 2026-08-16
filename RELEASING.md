# Releasing

little-auth-scim publishes to [crates.io](https://crates.io/crates/little-auth-scim) via a
tag-triggered GitHub Actions workflow (`.github/workflows/release.yml`), the same pattern used
by [mario/drey](https://github.com/mario/drey).

## How it works

1. Bump the version in `Cargo.toml` (`version = "X.Y.Z"`) on a normal PR into `main`, reviewed
   like any other change.
2. Once that PR is merged, tag the commit on `main`: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The tag push triggers three jobs:
   - **`verify`**: re-runs the full gate against the tagged commit (a tag push skips the PR
     run entirely, so this redoes it) -- `cargo fmt --check`, `cargo clippy -D warnings`,
     `cargo test --workspace`, doctest, `cargo publish --dry-run`. Also checks that the tagged
     commit is actually an ancestor of `main` (a tag can point anywhere; without this check,
     tagging is a way around every branch protection the repo has) and that the tag's version
     matches `Cargo.toml`'s (catching the classic "forgot to bump the version" mistake before
     it burns a crates.io version number, which can never be reused).
   - **`github_release`**: creates the GitHub Release immediately, with auto-generated notes.
     Doesn't wait on approval -- the release page should exist as soon as the tag does.
   - **`publish`**: gated behind the `crates-io` GitHub Environment, which requires a manual
     approval from a listed reviewer before the job runs. This is the actual "are we sure"
     gate -- a stray or accidental tag push can never publish on its own. Uses crates.io's
     [Trusted Publishing](https://crates.io/docs/trusted-publishing) (OIDC), not a stored
     `CARGO_REGISTRY_TOKEN` secret -- nothing long-lived to leak or rotate.
4. Approve the `publish` job (Actions tab -> the running workflow run -> Review deployments),
   or from the CLI: `gh run list --workflow=release.yml` then `gh run view <run-id>` for the
   review link.

## One-time setup already done

- The `crates-io` environment exists on this repo with `mario` as a required reviewer
  (repo Settings -> Environments -> crates-io -> Deployment protection rules). Add more
  reviewers there if the maintainer set grows.

## One-time setup NOT yet done (needs a human with crates.io access)

- **Trusted Publishing must be configured on crates.io itself** before the first real
  publish will work: crates.io -> this crate's settings (or, before the crate exists at all,
  crates.io's "pending publisher" flow) -> add a GitHub Actions trusted publisher pointing at
  `little-auth/little-auth-scim`, workflow `release.yml`, environment `crates-io`. This is a
  web UI action tied to a crates.io account; nothing in this repo or CI can do it. See
  <https://crates.io/docs/trusted-publishing> for the exact steps.
- Until Trusted Publishing is configured, the `publish` job will fail at the
  `rust-lang/crates-io-auth-action` step with an authentication error -- that's expected, not
  a bug in the workflow.
- The actual first release (0.1.0) still has its own separate checklist in
  [#3](https://github.com/little-auth/little-auth-scim/issues/3) -- this document describes
  the mechanism, not "is 0.1.0 ready to ship."

## Notes

- No `CHANGELOG.md` exists yet, so release notes come entirely from
  `gh release create --generate-notes` (the commit/PR list since the last tag). Add a
  `CHANGELOG.md` later and this workflow would need a small change to pull curated notes from
  it (see how `drey`'s `release.yml` does this) -- not done here since there's nothing to pull
  from yet.
- Re-running the workflow on an existing tag is safe for the release-notes step (`gh release
  edit`) but `cargo publish` will simply fail on a version that's already live on crates.io --
  crates.io versions are immutable, which is exactly the property `verify`'s version-match
  check exists to protect before that point.
