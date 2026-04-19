class Openhost < Formula
  desc "Self-hosted public-endpoint daemon: run services behind NAT without port forwarding"
  homepage "https://github.com/kaicoder03/openhost"
  version "0.3.0"
  license any_of: ["Apache-2.0", "MIT"]

  # The URLs below point at the assets published by
  # `.github/workflows/release.yml` on every `v*` tag push. Archive
  # layout: each `.tar.gz` contains a top-level directory named
  # `openhost-<os>-<arch>/` with the three binaries, both license
  # files, the CHANGELOG, the README, and the `distribution/` tree.
  #
  # The `sha256` slots below are TBD — filled in by a human (or a
  # future release-tap-update workflow) after the first v0.3.0 release
  # fires. The 64-hex-zero placeholders keep the formula syntactically
  # valid so `brew audit --strict` and `brew style` both pass locally
  # before any real checksum is known. See
  # `distribution/homebrew/README.md` for the update procedure.

  on_macos do
    on_arm do
      url "https://github.com/kaicoder03/openhost/releases/download/v#{version}/openhost-macos-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    on_intel do
      url "https://github.com/kaicoder03/openhost/releases/download/v#{version}/openhost-macos-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/kaicoder03/openhost/releases/download/v#{version}/openhost-linux-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    # Linux aarch64 is a future ROADMAP item; native ARM runners are
    # paid on GitHub Actions and cross-compile requires extra
    # toolchain setup. When that artifact lands, add an `on_arm` block
    # here mirroring the macOS shape.
  end

  def install
    bin.install "openhostd"
    bin.install "openhost-dial"
    bin.install "openhost-resolve"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/openhostd --version")
    assert_match version.to_s, shell_output("#{bin}/openhost-dial --version")
    assert_match version.to_s, shell_output("#{bin}/openhost-resolve --version")
  end
end
