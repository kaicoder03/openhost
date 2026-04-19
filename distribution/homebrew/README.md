# Homebrew formula

`openhost.rb` is a Homebrew formula that installs the three openhost binaries — `openhostd`, `openhost-dial`, `openhost-resolve` — on macOS (Apple Silicon or Intel) and Linux x86_64.

The formula downloads the matching pre-built archive from [GitHub Releases](https://github.com/kaicoder03/openhost/releases) (produced by `.github/workflows/release.yml` on every `v*` tag) and drops the binaries into `bin/`.

## Install (once the tap exists)

```bash
brew tap kaicoder03/openhost
brew install openhost
```

That requires a companion repo at `github.com/kaicoder03/homebrew-openhost` holding the formula at `Formula/openhost.rb`. The repo does not exist yet — see the maintainer section below for the one-time setup.

## Install directly from this repo (pre-tap testing)

Useful while the tap repo is being set up, or for anyone who wants to install a formula from a branch before it lands on the tap:

```bash
brew install --HEAD https://raw.githubusercontent.com/kaicoder03/openhost/main/distribution/homebrew/openhost.rb
```

`--HEAD` bypasses the `version` + `url` + `sha256` pinning and builds/downloads from the URL directly. Drop the flag once the SHA256 placeholders in `openhost.rb` have been filled in with real values against a tagged release.

> **No checksum verification on the `--HEAD` path.** `--HEAD` installs whatever `raw.githubusercontent.com` returns; the artifact is not integrity-checked against a pinned SHA256. Only install via this command from a branch + raw URL you trust (the main repo, a known contributor's fork, etc.). For untrusted sources use the tapped install, which does verify the `sha256` in the formula.

## Maintainer notes: setting up the tap repo

These are one-time steps for a project maintainer after the first binary release (v0.3.0+) is live.

1. **Create the tap repo.** On GitHub, create a new public repo at `github.com/kaicoder03/homebrew-openhost`. The name prefix `homebrew-` is what lets `brew tap kaicoder03/openhost` resolve it — Homebrew strips `homebrew-` and matches on the remaining path. Do not change the prefix. An empty repo is fine; no README is required.

2. **Copy the formula.** Clone the new repo and copy this directory's `openhost.rb` to `Formula/openhost.rb` in the tap repo:

   ```bash
   git clone git@github.com:kaicoder03/homebrew-openhost.git
   cd homebrew-openhost
   mkdir -p Formula
   cp ../openhost/distribution/homebrew/openhost.rb Formula/openhost.rb
   ```

3. **Update the SHA256 values.** After a tagged release has published artifacts, download each of the platform archives and compute their SHA256:

   ```bash
   for asset in \
     openhost-macos-aarch64.tar.gz \
     openhost-macos-x86_64.tar.gz \
     openhost-linux-x86_64.tar.gz; do
     curl -sSL -o "$asset" \
       "https://github.com/kaicoder03/openhost/releases/download/v0.3.0/$asset"
     echo "$asset: $(shasum -a 256 "$asset" | cut -d' ' -f1)"
   done
   ```

   Replace each `"0000…0000"` placeholder in `Formula/openhost.rb` with the matching checksum, bump the `version` line to the release tag (minus the `v` prefix), then commit + push the tap repo.

   > **Keep the loop's `v0.3.0` and the formula's `version` in lockstep.** The `curl` URL above hardcodes `v0.3.0`; when releasing v0.3.1 or later, edit both the loop tag and the `version` line in `openhost.rb` to the new tag. Mismatches produce a formula pinned to one version that downloads a different one — a silent checksum failure at install time.

4. **Verify.** From a clean shell:

   ```bash
   brew tap kaicoder03/openhost
   brew install openhost
   openhostd --version
   brew test openhost
   ```

   The `test do` block in the formula runs `--version` against each binary and asserts it contains the expected version string.

5. **Future: automate this.** A follow-up PR (maintainer-only) can add a second GitHub Actions workflow triggered by successful `release.yml` runs that computes the SHA256 for each artifact, edits `Formula/openhost.rb` in the tap repo, and opens a PR. For now the bump is manual — it runs once per release and takes ~2 minutes with the loop above.

## What the formula does *not* do

- **No self-signing or notarization.** The binaries are unsigned; macOS Gatekeeper will quarantine them on first run (`xattr -dr com.apple.quarantine $(brew --prefix)/bin/openhostd` clears the attribute). Paid dev-cert signing is a future ROADMAP item.
- **No service-manager install.** The formula drops binaries only. For `launchctl` / `systemctl` integration, see [`../README.md`](../README.md) — the service-manager files under `distribution/launchd/` and `distribution/systemd/` are installed manually.
- **No config scaffolding.** Operators write their own `~/.config/openhost/daemon.toml`. The [install guide](https://kaicoder03.github.io/openhost/guides/install/) and [quickstart](https://kaicoder03.github.io/openhost/guides/quickstart/) walk through the first-run setup.
