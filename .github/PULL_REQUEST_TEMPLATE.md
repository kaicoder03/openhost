<!--
Thank you for contributing to openhost.

Before opening a PR, please ensure:
- The code is formatted (`cargo fmt`) and passes clippy (`cargo clippy --workspace -- -D warnings`).
- Tests pass (`cargo test --workspace`).
- If you changed anything under `spec/`, the compatibility implications are stated explicitly below.
-->

## Summary

<!-- 1-3 sentences describing the change and why. -->

## Type of change

- [ ] Bug fix (behavior change in an existing feature)
- [ ] New feature (adds capability; backwards-compatible)
- [ ] Protocol change (requires spec update and compatibility note below)
- [ ] Documentation / website only
- [ ] Internal / refactor (no user-facing change)

## Compatibility (required for protocol changes)

<!-- If this PR touches `spec/`: does it break existing implementations? Which parts of the protocol version are affected? -->

## Verification

<!-- How did you verify this works? cargo test output, manual steps, screenshots, etc. -->

## Checklist

- [ ] `cargo fmt` and `cargo clippy` pass
- [ ] Relevant tests added or updated
- [ ] Documentation updated where appropriate
