use std::str::FromStr;

use clap::{ArgAction, Args, Parser, Subcommand};
use iroh::{EndpointId, RelayUrl};

const RELAY_URL_HELP: &str = "use this relay server, replacing the defaults (repeatable)";

#[derive(Parser, Debug)]
#[command(
    name = "pigeons",
    about = "carrier pigeons for your SSH connections. no IP addresses, no problem."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Set up a roost. Accepts incoming pigeons and delivers them to your local sshd
    Roost(RoostArgs),
    /// Send a pigeon to a remote roost, opening a local tunnel for SSH
    Fly(FlyArgs),
    /// Train a pigeon route (add an SSH config entry for a remote roost)
    Add(AddArgs),
    /// See what pigeon routes are configured
    List,
    /// Forget a pigeon route (remove an SSH config entry)
    Remove(RemoveArgs),
    /// Coop management: install or uninstall pigeons as a system service
    Service {
        #[command(subcommand)]
        op: ServiceCmd,
    },
    /// Print the version number
    Version,
    /// Verify this binary can start up cleanly. Used by the OTA receiver
    /// (via `iroh-ota`'s `TestCommand::SelfTest`) against a staged binary
    /// before flipping the symlink. Exits 0 on success.
    #[command(hide = true)]
    SelfTest,
}

#[derive(Subcommand, Clone, Debug)]
pub enum ServiceCmd {
    /// Build a permanent coop (install as system service)
    Install {
        #[arg(long, default_value = "22")]
        ssh_port: u16,

        #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
        relay_url: Vec<String>,
    },
    /// Tear down the coop (uninstall system service)
    Uninstall,
    /// Restart the running service
    Restart,
    /// Show service status
    Status,
    /// Show service logs
    Log,
}

#[derive(Args, Clone, Debug)]
pub struct RoostArgs {
    /// Which port your local sshd is nesting on
    #[arg(long, default_value = "22")]
    pub ssh_port: u16,

    /// Use a throwaway identity instead of persisting keys
    #[arg(short, long, default_value_t = false)]
    pub ephemeral: bool,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    pub relay_url: Vec<String>,
}

#[derive(Args, Clone, Debug)]
pub struct FlyArgs {
    /// The public key of the remote roost to fly to
    #[arg()]
    pub public_key: String,

    /// Bridge stdin/stdout instead of binding a local port (for use as SSH ProxyCommand)
    #[arg(long, default_value_t = false)]
    pub stdio: bool,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    pub relay_url: Vec<String>,
}

#[derive(Args, Clone, Debug)]
pub struct AddArgs {
    /// The endpoint ID of the remote roost
    #[arg(long)]
    pub id: String,

    /// A friendly name for this pigeon route (used as SSH Host name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct RemoveArgs {
    /// The name of the pigeon route to remove
    #[arg()]
    pub name: String,
}

fn main() -> anyhow::Result<()> {
    // Must happen before any tokio runtime exists: the watchdog builds its
    // own current-thread runtime and `process::exit`s without returning, and
    // doing that from inside an outer runtime would panic.
    #[cfg(target_os = "linux")]
    pigeons::ota::detect_and_run_watchdog();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::Roost(args) => {
            let ssh_dir = pigeons::home_ssh_dir()?;
            let mut builder = if args.ephemeral {
                pigeons::Tunnel::builder_ephemeral()
            } else {
                pigeons::Tunnel::builder_from_ssh_dir(ssh_dir)?
            };
            builder.roost = Some(pigeons::RoostConfig {
                ssh_port: args.ssh_port,
            });
            for url in &args.relay_url {
                builder.relay_urls.push(
                    RelayUrl::from_str(url)
                        .map_err(|e| anyhow::anyhow!("invalid relay URL '{url}': {e}"))?,
                );
            }

            // Service mode (root): wire up the OTA receiver if the binary
            // was built with PIGEONS_OTA_PUBKEY. Skipped for unprivileged
            // and ephemeral runs because the SystemdApplier writes into
            // /opt/pigeons and shells out to `systemctl restart`.
            #[cfg(target_os = "linux")]
            if self_runas::is_elevated() {
                if let Some(factory) = pigeons::ota::build_handler()? {
                    builder.extra_protocols.push(factory);
                }
            }

            let tunnel = builder.build().await?;
            let id = tunnel.endpoint().id();

            // If running as root (service mode), publish the endpoint ID
            // so unprivileged users can read it via 'pigeons status'
            if self_runas::is_elevated() {
                let dir = std::path::Path::new("/etc/pigeons");
                std::fs::create_dir_all(dir)?;
                std::fs::write(dir.join("endpoint_id"), id.to_string().as_bytes())?;
                // world-readable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        dir.join("endpoint_id"),
                        std::fs::Permissions::from_mode(0o644),
                    )?;
                }
            }

            // Tell the OTA watchdog (if any) we came up healthy. Best-effort:
            // a failure here means the next push will time out and roll back,
            // which is the correct behavior — but it shouldn't take down a
            // roost that's otherwise running fine.
            #[cfg(target_os = "linux")]
            if self_runas::is_elevated() {
                if let Err(e) = pigeons::ota::write_ready_file().await {
                    tracing::warn!("failed to write OTA ready file: {e:#}");
                }
            }

            println!("roost is running! id: {}", id);
            tokio::signal::ctrl_c().await?;
            tunnel.close().await?;
            Ok(())
        }
        Cmd::Fly(args) => {
            let mut builder = pigeons::Tunnel::builder_ephemeral();
            for url in &args.relay_url {
                builder.relay_urls.push(
                    RelayUrl::from_str(url)
                        .map_err(|e| anyhow::anyhow!("invalid relay URL '{url}': {e}"))?,
                );
            }
            let tunnel = builder.build().await?;
            let remote_id = EndpointId::from_str(&args.public_key)?;

            if args.stdio {
                tunnel.fly_stdio(remote_id).await?;
            } else {
                let fut = tunnel.fly(remote_id);
                tokio::select! {
                    res = fut => {
                        if let Err(err) = res {
                            eprintln!("error: {err}");
                        };
                    }
                    _ = tokio::signal::ctrl_c() => {
                        println!("shutting down...");
                    }
                };
            }

            tunnel.close().await?;
            Ok(())
        }
        Cmd::Add(args) => {
            let name = args.name.unwrap_or_else(|| {
                let id = &args.id;
                format!("pigeon-{}", &id[..8.min(id.len())])
            });
            let name = name.trim();
            if name.is_empty() {
                anyhow::bail!("host name cannot be empty");
            }
            if name.chars().any(|c| c.is_whitespace()) {
                anyhow::bail!("host name '{name}' cannot contain whitespace");
            }
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
            {
                anyhow::bail!(
                    "host name '{name}' contains invalid characters (use letters, digits, hyphens, dots, or underscores)"
                );
            }
            let endpoint_id = EndpointId::from_str(&args.id)?;
            pigeons::add_tunnel_host(name, &endpoint_id)?;
            println!("Pigeon route '{name}' added to ~/.ssh/config");
            println!();
            println!("  Fly with: ssh <user>@{name}");
            Ok(())
        }
        Cmd::List => {
            let entries = pigeons::list_tunnel_hosts()?;
            if entries.is_empty() {
                println!("No pigeon routes configured.");
            } else {
                println!("Pigeon routes:");
                println!();
                for entry in &entries {
                    println!("  {:<20} {}", entry.name, entry.endpoint_id);
                }
            }
            Ok(())
        }
        Cmd::Remove(args) => {
            pigeons::remove_tunnel_host(&args.name)?;
            println!("Pigeon route '{}' removed.", args.name);
            Ok(())
        }
        Cmd::Version => {
            println!(
                "pigeons v{} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("GIT_HASH")
            );
            Ok(())
        }
        Cmd::SelfTest => Ok(()),
        Cmd::Service { op } => {
            match op {
                ServiceCmd::Install {
                    ssh_port,
                    relay_url,
                } => {
                    // Resolve and validate the binary path *before* elevating,
                    // so the user sees any error in their own terminal.
                    let binary_path = pigeons::resolve_binary_path()?;

                    if !self_runas::is_elevated() {
                        self_runas::admin()?;
                        return Ok(());
                    }

                    pigeons::install_service(pigeons::ServiceParams {
                        ssh_port,
                        relay_url,
                        binary_path,
                    })
                    .await?;
                    println!("Pigeons service installed.");
                    Ok(())
                }
                ServiceCmd::Uninstall => {
                    if !self_runas::is_elevated() {
                        self_runas::admin()?;
                        return Ok(());
                    }

                    pigeons::uninstall_service().await?;
                    println!("Pigeons service uninstalled.");
                    Ok(())
                }
                ServiceCmd::Restart => {
                    if !self_runas::is_elevated() {
                        self_runas::admin()?;
                        return Ok(());
                    }

                    pigeons::restart_service().await?;
                    println!("Pigeons service restarted.");
                    Ok(())
                }
                ServiceCmd::Status => {
                    match pigeons::service_endpoint_id() {
                        Some(id) => {
                            println!("Service:       running");
                            println!();
                            println!("  Roost ID: {id}");
                            println!();
                            println!("  Connect with:");
                            println!("    pigeons fly {id}");
                            println!("    pigeons add --id {id} --name my-roost");
                        }
                        None => {
                            println!("Service:       not installed");
                        }
                    }
                    Ok(())
                }
                ServiceCmd::Log => {
                    pigeons::service_log()?;
                    Ok(())
                }
            }
        }
    }
}
