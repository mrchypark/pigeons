//! Over-the-air update receiver, gluing [`iroh_updater`] to pigeons.
//!
//! Linux-only. The receiver runs alongside a roost installed as a systemd
//! service: it shares the roost's iroh endpoint (registering an extra ALPN on
//! the same router), uses the [`SystemdApplier`] to flip the on-disk symlink
//! and trigger `systemctl restart pigeons.service`, and relies on
//! [`iroh_updater::watchdog`] to roll back if the new binary fails to come up.
//!
//! On-disk layout under [`OTA_BASE`]:
//!
//! ```text
//! /opt/pigeons/
//!   versions/<v>/pigeons      committed binaries
//!   current -> versions/<v>   atomic symlink (systemd ExecStart points here)
//!   staging/<v>/artifact      in-flight downloads
//!   state                     postcard OtaStateSnapshot
//!   ready                     touched by main() once the roost is up
//! ```
//!
//! The artifact verifying key is embedded at build time via the
//! `PIGEONS_OTA_PUBKEY` env var (32 bytes, hex-encoded). Without that env var
//! set at build time, [`build_handler`] returns `None` and the roost runs
//! without OTA.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh_blobs::store::mem::MemStore;
use iroh_updater::{
    ALPN, FileStatePersistence, UpdatePaths, OtaServerBuilder, OtaStateSnapshot, ShellSystemctl,
    SymlinkConfig, SystemdApplier, SystemdConfig, TestCommand, VerifyingKey,
    iroh_base::PublicKey,
    persistence::StatePersistence,
    watchdog::{self, WatchdogConfig},
};

use crate::tunnel::ExtraProtocolFactory;

/// Filesystem root for the OTA layout.
pub const OTA_BASE: &str = "/opt/pigeons";

/// Filename of the pigeons binary inside each `versions/<v>/` directory.
pub const OTA_BINARY_NAME: &str = "pigeons";

/// systemd unit the [`SystemdApplier`] restarts after a successful flip.
pub const OTA_UNIT_NAME: &str = "pigeons.service";

/// Path of the file the running roost touches once it has started up
/// successfully. The watchdog polls this to decide between Completed and
/// rollback.
pub const READY_FILE: &str = "/opt/pigeons/ready";

/// Path of the trusted-pusher allowlist. One [`EndpointId`] per line; blank
/// lines and `#`-prefixed comments are ignored. Missing or empty file
/// degenerates to deny-all (the iroh-ota AccessLimit default).
pub const ALLOWLIST_FILE: &str = "/etc/pigeons/ota_allowed_pushers";

/// Watchdog timeout: the new binary has this many seconds to touch
/// [`READY_FILE`] before the watchdog rolls back.
const WATCHDOG_TIMEOUT_SECS: u64 = 30;

/// Operator-supplied artifact verifying key, embedded at build time. Hex,
/// 64 chars (32 bytes). Absent -> OTA disabled.
const EMBEDDED_VERIFYING_KEY_HEX: Option<&str> = option_env!("PIGEONS_OTA_PUBKEY");

/// First call in `main()`: if this process was started by the watchdog as a
/// re-exec, hijack it and don't return. Otherwise no-op.
pub fn detect_and_run_watchdog() {
    watchdog::detect_and_run();
}

/// Parsed embedded verifying key. `Ok(None)` means OTA wasn't configured at
/// build time; `Err` means the configured value didn't decode.
pub fn embedded_verifying_key() -> Result<Option<VerifyingKey>> {
    let Some(hex) = EMBEDDED_VERIFYING_KEY_HEX else {
        return Ok(None);
    };
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(None);
    }
    let bytes = decode_hex32(hex)
        .with_context(|| format!("PIGEONS_OTA_PUBKEY must be 64 hex chars, got {:?}", hex))?;
    let public = PublicKey::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("PIGEONS_OTA_PUBKEY is not a valid ed25519 key: {e}"))?;
    Ok(Some(VerifyingKey::from_public(public)))
}

/// Build a factory that constructs the OTA receiver against the bound
/// endpoint. Returns `Ok(None)` when OTA isn't configured (no embedded
/// verifying key), so the caller can transparently skip wiring it up.
///
/// All fail-fast checks (key parsing, allowlist parsing) happen synchronously
/// before the closure is returned — the closure itself runs once the endpoint
/// is bound, and only does work that genuinely needs the endpoint.
///
/// Caller must already be running as root: the [`SystemdApplier`] writes into
/// [`OTA_BASE`] and shells out to `systemctl restart`.
pub fn build_handler() -> Result<Option<ExtraProtocolFactory>> {
    let Some(verifying_key) = embedded_verifying_key()? else {
        tracing::info!("OTA disabled: PIGEONS_OTA_PUBKEY was not set at build time");
        return Ok(None);
    };

    let allowed = load_allowlist(Path::new(ALLOWLIST_FILE))
        .with_context(|| format!("reading {ALLOWLIST_FILE}"))?;
    if allowed.is_empty() {
        tracing::warn!(
            "OTA enabled but allowlist at {ALLOWLIST_FILE} is empty/missing — all pushes will be denied"
        );
    } else {
        tracing::info!("OTA enabled with {} allowed pusher(s)", allowed.len());
    }

    let factory: ExtraProtocolFactory = Box::new(move |endpoint| {
        Box::pin(async move {
            let base = PathBuf::from(OTA_BASE);
            let paths = UpdatePaths::new(&base);
            paths
                .ensure_dirs()
                .await
                .with_context(|| format!("creating OTA layout at {}", base.display()))?;

            let blob_store = MemStore::new();
            let applier = SystemdApplier::new(
                ShellSystemctl,
                SystemdConfig {
                    symlink: SymlinkConfig::new(paths.clone(), OTA_BINARY_NAME),
                    unit_name: OTA_UNIT_NAME.into(),
                    watchdog: Some(WatchdogConfig {
                        paths: paths.clone(),
                        ready_file: PathBuf::from(READY_FILE),
                        state_file: paths.state_file(),
                        timeout_secs: WATCHDOG_TIMEOUT_SECS,
                    }),
                },
            );

            let handler =
                OtaServerBuilder::new(applier, FileStatePersistence::new(paths.state_file()))
                    .verifying_key(verifying_key)
                    .target_triple(env!("TARGET"))
                    .endpoint(endpoint)
                    .blob_store((*blob_store).clone())
                    .paths(paths)
                    .test_command(TestCommand::SelfTest {
                        args: vec!["--self-test".into()],
                    })
                    .allow_all(allowed)
                    .access_limit()
                    .await
                    .map_err(|e| anyhow::anyhow!("building OTA handler: {e}"))?;

            Ok((ALPN.to_vec(), Box::new(handler) as Box<_>))
        })
    });

    Ok(Some(factory))
}

/// Touch the watchdog ready-file. Roost's `main()` calls this once startup is
/// complete; the watchdog observes the file and persists `Completed` instead
/// of timing out and rolling back.
///
/// Idempotent: removing-then-creating ensures a stale file from a prior
/// process doesn't satisfy a fresh watchdog before *this* roost has actually
/// finished booting. (The watchdog spawns just before the parent restart, so
/// it starts watching from a clean slate, but a leftover ready file would
/// short-circuit it.)
pub async fn write_ready_file() -> Result<()> {
    let path = Path::new(READY_FILE);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let _ = tokio::fs::remove_file(path).await;
    tokio::fs::write(path, b"ok\n")
        .await
        .with_context(|| format!("writing ready file at {}", path.display()))?;
    Ok(())
}

/// Read and return the persisted OTA state, if any.
pub async fn read_state_snapshot() -> Result<Option<OtaStateSnapshot>> {
    let path = UpdatePaths::new(OTA_BASE).state_file();
    let persistence = FileStatePersistence::new(path);
    persistence
        .load()
        .await
        .map_err(|e| anyhow::anyhow!("reading OTA state: {e}"))
}

fn load_allowlist(path: &Path) -> Result<Vec<EndpointId>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let id = EndpointId::from_str(line).with_context(|| {
            format!("{}:{}: not a valid endpoint id: {raw:?}", path.display(), lineno + 1)
        })?;
        out.push(id);
    }
    Ok(out)
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("not a hex digit: {:?}", b as char),
    }
}
