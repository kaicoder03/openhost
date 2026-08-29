## 2026-07-28 - Atomic Mode-0600 Creation for Sensitive Files
**Vulnerability:** Opening or creating files (seeds, DTLS certificates, identity keys, allowlists) with default `File::create` or `fs::write` prior to calling `set_permissions` leaves a TOCTOU window where local unprivileged users can read sensitive material before permissions are tightened.
**Learning:** Functions like `std::fs::write` or `File::create` apply the process umask, which typically results in `0644` or `0666` modes until a subsequent `set_permissions` async or sync call completes.
**Prevention:** Use `OpenOptions` with `OpenOptionsExt::mode(0o600)` under `#[cfg(unix)]` at file creation time so the file descriptor is opened with restricted mode atomically upon creation.
