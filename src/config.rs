use std::{
    env, io,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    telemetry_enabled: Option<bool>,
}

impl Config {
    /// Whether sending metrics to the embedded or configured iroh-services endpoint is enabled.
    pub fn telemetry_enabled(&self) -> bool {
        self.telemetry_enabled.unwrap_or(false)
    }

    /// Whether the user has made a telemetry choice yet.
    ///
    /// An unset key means we have never asked, which is what the first-run
    /// prompt keys off. It is distinct from an explicit `telemetry_enabled =
    /// false`: both keep telemetry off, but only the former should produce a
    /// question.
    pub fn telemetry_configured(&self) -> bool {
        self.telemetry_enabled.is_some()
    }

    /// Records a telemetry choice. Call [`Config::store`] to persist it.
    pub fn set_telemetry_enabled(&mut self, enabled: bool) {
        self.telemetry_enabled = Some(enabled);
    }

    /// Loads the config every pigeons run should use: the per-user config,
    /// with any key it leaves unset taken from the machine-wide config.
    ///
    /// The layering exists for the service. A roost installed with `pigeons
    /// service install` runs as root, whose per-user config is its own and
    /// almost always absent, so the machine-wide file written at install time
    /// is what carries the answer over.
    pub async fn load() -> Result<Self> {
        let user_path = Self::config_path()?;
        let Ok(system_path) = Self::system_config_path() else {
            return Self::load_from(&user_path).await;
        };
        Self::load_with_fallback(&user_path, &system_path).await
    }

    /// Loads only the per-user config, ignoring the machine-wide fallback.
    ///
    /// The first-run question is about this user's setting, so it has to see
    /// an unanswered user config as unanswered even on a machine that already
    /// has a system-wide answer.
    pub async fn load_user() -> Result<Self> {
        Self::load_from(&Self::config_path()?).await
    }

    async fn load_with_fallback(user_path: &Path, system_path: &Path) -> Result<Self> {
        let mut config = Self::load_from(user_path).await?;
        config.fill_unset_from(Self::load_from(system_path).await?);
        Ok(config)
    }

    /// Takes every key this config leaves unset from `fallback`.
    fn fill_unset_from(&mut self, fallback: Self) {
        self.telemetry_enabled = self.telemetry_enabled.or(fallback.telemetry_enabled);
    }

    /// Read and parse the config at `path`. Loading is read-only: a config that
    /// has not been written yet simply yields the defaults.
    async fn load_from(path: &Path) -> Result<Self> {
        let config_bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed reading config at {}", path.display()));
            }
        };

        toml::from_slice(&config_bytes)
            .with_context(|| format!("failed parsing config at {}", path.display()))
    }

    /// Loads the config, falling back to the default config on error.
    pub async fn load_or_default() -> Self {
        match Self::load().await {
            Ok(config) => config,
            Err(err) => {
                tracing::error!("failed to load config, using default: {err:#?}");
                Self::default()
            }
        }
    }

    pub async fn store(&self) -> Result<()> {
        self.store_to(&Self::config_path()?).await
    }

    async fn store_to(&self, config_file_path: &Path) -> Result<()> {
        fs::create_dir_all(config_file_path.parent().expect("joined path")).await?;

        let mut file = File::options()
            .write(true)
            .truncate(true)
            .create(true)
            .open(config_file_path)
            .await?;
        file.write_all(toml::to_string(self)?.as_bytes()).await?;
        Ok(())
    }

    /// Writes the config to `path` and makes it readable by everyone.
    ///
    /// This is how the machine-wide config is written: every unprivileged run
    /// reads it as a fallback, and the umask of the root shell doing the
    /// installing would otherwise decide whether they can.
    async fn store_world_readable(&self, path: &Path) -> Result<()> {
        self.store_to(path).await?;

        #[cfg(unix)]
        {
            use std::{fs::Permissions, os::unix::fs::PermissionsExt};

            let dir = path.parent().expect("joined path");
            fs::set_permissions(dir, Permissions::from_mode(0o755)).await?;
            fs::set_permissions(path, Permissions::from_mode(0o644)).await?;
        }

        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("can't figure out config dir on this system")?
            .join("pigeons");
        Ok(config_dir.join("config.toml"))
    }

    /// Path of the machine-wide config, alongside the endpoint ID the roost
    /// publishes for `pigeons service status`.
    pub fn system_config_path() -> Result<PathBuf> {
        let dir = match env::consts::OS {
            "linux" | "macos" => Path::new("/etc/pigeons"),
            "windows" => Path::new("C:\\ProgramData\\pigeons"),
            other => anyhow::bail!("no machine-wide config location on {other}"),
        };
        Ok(dir.join("config.toml"))
    }

    /// Path of the per-user config belonging to the owner of `home`.
    ///
    /// [`Config::config_path`] cannot answer this: it reports the location for
    /// whoever is running, and an elevated install needs the location of the
    /// user who started it. The layouts here mirror what `dirs` reports for a
    /// default environment, which is the only thing we can know about another
    /// account.
    fn config_path_in(home: &Path) -> PathBuf {
        let relative = match env::consts::OS {
            "macos" => "Library/Application Support/pigeons/config.toml",
            "windows" => "AppData/Roaming/pigeons/config.toml",
            _ => ".config/pigeons/config.toml",
        };
        home.join(relative)
    }
}

/// Copies the installing user's telemetry choice into the machine-wide config
/// and reports what the service will do with it.
///
/// Call this from an elevated `pigeons service install`. The service runs as
/// root and reads root's config, so without this step it can never see the
/// answer the user gave in their own terminal.
///
/// # Errors
///
/// Returns an error when the machine-wide config cannot be written, which for
/// an unprivileged caller it cannot.
pub async fn publish_telemetry_choice_for_service() -> Result<bool> {
    let system_path = Config::system_config_path()?;
    let choice = installing_user_telemetry_choice().await;
    publish_telemetry_choice_to(&system_path, choice).await
}

async fn publish_telemetry_choice_to(system_path: &Path, choice: Option<bool>) -> Result<bool> {
    if let Some(enabled) = choice {
        let mut system = Config::load_from(system_path).await.unwrap_or_default();
        system.set_telemetry_enabled(enabled);
        system.store_world_readable(system_path).await?;
    }

    // Report what is on disk rather than what we just wrote: with nothing to
    // propagate, an answer an admin put there earlier still governs the service.
    Ok(Config::load_from(system_path)
        .await
        .unwrap_or_default()
        .telemetry_enabled())
}

/// The telemetry choice of the user who started an elevated command, if they
/// have recorded one.
///
/// `sudo` leaves the original account in `SUDO_USER`, which is the only pointer
/// an elevated unix process has back to the config of the person who answered
/// the question. Windows elevation keeps the same account, so there the running
/// user's own config is already the right one to read.
async fn installing_user_telemetry_choice() -> Option<bool> {
    let path = match env::var("SUDO_USER") {
        Ok(user) => config_path_for_user(&user)?,
        Err(_) => Config::config_path().ok()?,
    };

    Config::load_from(&path).await.ok()?.telemetry_enabled
}

/// Path of `user`'s config, or `None` when their home cannot be resolved.
fn config_path_for_user(user: &str) -> Option<PathBuf> {
    let home = homedir::home(user).ok()??;
    Some(Config::config_path_in(&home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let config = toml::from_str::<Config>("").unwrap();
        assert!(!config.telemetry_enabled());
    }

    /// The first-run prompt asks exactly when no choice has been recorded, so
    /// "off" and "never asked" have to stay distinguishable.
    #[test]
    fn declining_telemetry_still_counts_as_configured() {
        let unasked = toml::from_str::<Config>("").unwrap();
        assert!(!unasked.telemetry_configured());

        let declined = toml::from_str::<Config>("telemetry_enabled = false").unwrap();
        assert!(declined.telemetry_configured());
        assert!(!declined.telemetry_enabled());
    }

    /// A user who answered the question owns the answer, even on a machine
    /// whose service was installed with the opposite one.
    #[tokio::test]
    async fn user_config_wins_over_the_machine_wide_one() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        let system = dir.path().join("system.toml");
        fs::write(&user, "telemetry_enabled = false").await.unwrap();
        fs::write(&system, "telemetry_enabled = true")
            .await
            .unwrap();

        let config = Config::load_with_fallback(&user, &system).await.unwrap();

        assert!(!config.telemetry_enabled());
    }

    /// This is the case the service hits: root has no config of its own, and
    /// the answer lives in the machine-wide file written at install time.
    #[tokio::test]
    async fn machine_wide_config_fills_in_an_unanswered_user_config() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system.toml");
        fs::write(&system, "telemetry_enabled = true")
            .await
            .unwrap();

        let config = Config::load_with_fallback(&dir.path().join("absent.toml"), &system)
            .await
            .unwrap();

        assert!(config.telemetry_enabled());
    }

    #[tokio::test]
    async fn telemetry_stays_off_when_neither_layer_exists() {
        let dir = tempfile::tempdir().unwrap();

        let config =
            Config::load_with_fallback(&dir.path().join("user.toml"), &dir.path().join("sys.toml"))
                .await
                .unwrap();

        assert!(!config.telemetry_configured());
        assert!(!config.telemetry_enabled());
    }

    /// What `service install` does once elevated: the answer the user gave in
    /// their own terminal becomes the setting the root-owned service reads.
    #[tokio::test]
    async fn publishing_a_choice_writes_the_machine_wide_config() {
        for enabled in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let system = dir.path().join("pigeons").join("config.toml");

            let effective = publish_telemetry_choice_to(&system, Some(enabled))
                .await
                .unwrap();

            assert_eq!(effective, enabled);
            assert_eq!(
                Config::load_from(&system)
                    .await
                    .unwrap()
                    .telemetry_enabled(),
                enabled
            );
        }
    }

    /// Installing from a root shell leaves no `SUDO_USER` to trace back to, so
    /// there is nothing to propagate and an answer already on the machine has
    /// to survive the install.
    #[tokio::test]
    async fn publishing_nothing_keeps_the_existing_machine_wide_answer() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("config.toml");
        fs::write(&system, "telemetry_enabled = true")
            .await
            .unwrap();

        let effective = publish_telemetry_choice_to(&system, None).await.unwrap();

        assert!(effective);
    }

    #[tokio::test]
    async fn publishing_nothing_onto_a_bare_machine_leaves_the_service_opted_out() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("config.toml");

        let effective = publish_telemetry_choice_to(&system, None).await.unwrap();

        assert!(!effective);
        assert!(!system.exists(), "nothing to record, nothing to write");
    }

    /// Root writes this file, everyone reads it, and root's umask does not get
    /// a vote.
    #[cfg(unix)]
    #[tokio::test]
    async fn machine_wide_config_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("pigeons").join("config.toml");

        publish_telemetry_choice_to(&system, Some(true))
            .await
            .unwrap();

        let mode = fs::metadata(&system).await.unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        let dir_mode = fs::metadata(system.parent().unwrap())
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o755);
    }

    /// The elevated half of `service install` finds the invoking user's config
    /// by way of their home directory, which has to resolve for a real account.
    #[test]
    fn config_path_for_user_lands_in_that_users_home() {
        let me = whoami::username().expect("running as some user");

        let path = config_path_for_user(&me).expect("current user has a home directory");

        let home = homedir::my_home().unwrap().unwrap();
        assert!(path.starts_with(&home), "{path:?} is not under {home:?}");
        assert!(path.ends_with("pigeons/config.toml"), "{path:?}");
    }

    #[test]
    fn config_path_in_a_home_matches_the_platform_layout() {
        let path = Config::config_path_in(Path::new("/home/pigeon"));

        let expected = match env::consts::OS {
            "macos" => "/home/pigeon/Library/Application Support/pigeons/config.toml",
            "windows" => "/home/pigeon/AppData/Roaming/pigeons/config.toml",
            _ => "/home/pigeon/.config/pigeons/config.toml",
        };
        assert_eq!(path, Path::new(expected));
    }

    #[tokio::test]
    async fn stored_telemetry_choice_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");

        for enabled in [true, false] {
            let mut config = Config::default();
            config.set_telemetry_enabled(enabled);
            config.store_to(&path).await.unwrap();

            let loaded = Config::load_from(&path).await.unwrap();
            assert!(loaded.telemetry_configured());
            assert_eq!(loaded.telemetry_enabled(), enabled);
        }
    }

    /// Not having written a config yet is the normal case, not an error.
    #[tokio::test]
    async fn load_from_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();

        let config = Config::load_from(&dir.path().join("config.toml"))
            .await
            .unwrap();

        assert!(!config.telemetry_enabled());
    }

    /// Regression: `load` used to open the file with `create(true)` and no write
    /// access, which fails unconditionally, so settings on disk were silently
    /// discarded in favour of the defaults.
    #[tokio::test]
    async fn load_from_reads_settings_off_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "telemetry_enabled = true").await.unwrap();

        let config = Config::load_from(&path).await.unwrap();

        assert!(
            config.telemetry_enabled(),
            "settings on disk must take precedence over the defaults"
        );
    }
}
