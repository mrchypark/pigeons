use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
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

    pub async fn load() -> Result<Self> {
        let config_file_path = Self::config_path()?;
        tokio::fs::create_dir_all(config_file_path.parent().expect("joined path")).await?;

        let mut file = File::options()
            .read(true)
            .create(true)
            .open(&config_file_path)
            .await?;
        let mut config_bytes = Vec::new();
        file.read_to_end(&mut config_bytes).await?;

        let config = toml::from_slice(&config_bytes)
            .context(format!("failed parsing config at {config_file_path:?}"))?;
        Ok(config)
    }

    pub async fn store(&self) -> Result<()> {
        let config_file_path = Self::config_path()?;
        tokio::fs::create_dir_all(config_file_path.parent().expect("joined path")).await?;

        let mut file = File::options()
            .write(true)
            .create(true)
            .open(config_file_path)
            .await?;
        file.write_all(toml::to_string(self)?.as_bytes()).await?;
        Ok(())
    }

    /// On the first interactive run, ask whether to send anonymous statistics
    /// to the iroh developers and persist the answer so we only ask once.
    ///
    /// Does nothing if the choice was already made, or if stdin isn't a TTY
    /// (e.g. `fly --stdio` used as an SSH ProxyCommand).
    pub async fn maybe_prompt_telemetry() -> Result<()> {
        use std::io::{IsTerminal, Write};

        let mut config = Self::load().await.unwrap_or_default();
        if config.telemetry_enabled.is_some() || !std::io::stdin().is_terminal() {
            return Ok(());
        }

        print!(
            "Send anonymous statistics to the iroh developers to help improve iroh? [y/N] "
        );
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let yes = parse_yes(&answer);

        config.telemetry_enabled = Some(yes);
        config.store().await?;
        println!(
            "{}",
            if yes {
                "Thanks! Anonymous statistics enabled. Edit the config to change this later."
            } else {
                "No problem, anonymous statistics stay off."
            }
        );
        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("can't figure out config dir on this system")?
            .join("pigeons");
        Ok(config_dir.join("config.toml"))
    }
}

fn parse_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let config = toml::from_str::<Config>("").unwrap();
        assert_eq!(config.telemetry_enabled(), false);
    }

    #[test]
    fn yes_parsing() {
        for input in ["y", "Y\n", " yes ", "YES"] {
            assert!(parse_yes(input), "{input:?} should be yes");
        }
        for input in ["", "n", "no", "nope", "\n"] {
            assert!(!parse_yes(input), "{input:?} should not be yes");
        }
    }
}
