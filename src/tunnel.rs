use std::{path::PathBuf, str::FromStr};

use anyhow::{Context, Result, anyhow};
use iroh::{
    Endpoint, EndpointId, RelayUrl, SecretKey,
    endpoint::{RelayMode, presets},
    protocol::{DynProtocolHandler, Router},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    protocol::PigeonsProtocol,
    ssh::{self, dot_ssh_secret_key},
};

#[derive(Debug)]
pub struct RoostConfig {
    pub ssh_port: u16,
}

impl Default for RoostConfig {
    fn default() -> Self {
        Self { ssh_port: 22 }
    }
}

const IROH_SERVICES_KEY: &str = "servicesaaqk6brwi76ssyn7ipoytif2eghedcurlkrht4vtaqlyvns6ujddxm4k4n7wy3domsbl5bfbkebpur534vlsssggjtlakkxufnk63olwcaaa";

pub struct TunnelBuilder {
    /// optional roost role configuration to expose a local ssh server
    /// through the tunnel
    pub roost: Option<RoostConfig>,
    /// ED25519 key to use to secure tunnel communications, the endpoint ID that
    /// identifies the tunnel is the public half of this keypair
    pub secret_key: SecretKey,
    /// the set of iroh relay urls to use. Empty set will default to public
    /// relay servers run by number 0
    pub relay_urls: Vec<RelayUrl>,
    /// iroh services client for telemetry aggregation
    pub isvc_client_secret: Option<String>,
    /// Extra `(ALPN, handler)` pairs to register on the router alongside the
    /// pigeons protocol. Used by callers to attach the iroh-ota receiver
    /// without leaking iroh-ota's types into this module.
    pub extra_protocols: Vec<(Vec<u8>, Box<dyn DynProtocolHandler>)>,
}

impl std::fmt::Debug for TunnelBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelBuilder")
            .field("roost", &self.roost)
            .field("relay_urls", &self.relay_urls)
            .field(
                "isvc_client_secret",
                &self.isvc_client_secret.as_ref().map(|_| "..."),
            )
            .field("extra_protocols", &self.extra_protocols.len())
            .finish_non_exhaustive()
    }
}

impl Default for TunnelBuilder {
    fn default() -> Self {
        TunnelBuilder {
            roost: None,
            secret_key: SecretKey::generate(),
            relay_urls: Vec::new(),
            isvc_client_secret: None,
            extra_protocols: Vec::new(),
        }
    }
}

impl TunnelBuilder {
    fn new(secret_key: SecretKey) -> Self {
        TunnelBuilder {
            roost: None,
            secret_key,
            relay_urls: vec![],
            isvc_client_secret: None,
            extra_protocols: Vec::new(),
        }
    }

    pub async fn build(self) -> Result<Tunnel> {
        tracing::debug!("building tunnel, roost={}", self.roost.is_some());
        let mut builder = Endpoint::builder(presets::N0).secret_key(self.secret_key.clone());

        if !self.relay_urls.is_empty() {
            tracing::debug!("using {} custom relay URLs", self.relay_urls.len());
            let relay_map = self.relay_urls.iter().cloned().collect();
            builder = builder.relay_mode(RelayMode::Custom(relay_map));
        }

        let endpoint = builder.bind().await?;
        tracing::info!("endpoint bound, id={}", endpoint.id());

        let secret = iroh_services::ApiSecret::from_str(IROH_SERVICES_KEY).unwrap();

        let client = iroh_services::Client::builder(&endpoint)
            .api_secret(secret.clone())?
            .build()
            .await?;

        let client2 = client.clone();
        let remote_id = secret.addr().id;
        // TODO - store & gracefully close task
        tokio::spawn(async move {
            if let Err(err) = client2
                .grant_capability(
                    remote_id,
                    vec![iroh_services::caps::NetDiagnosticsCap::GetAny],
                )
                .await
            {
                eprintln!("Failed to grant capability: {err:?}");
            }
        });

        // 5. Set up a ClientHost so iroh-services can dial *back* into this endpoint.
        //    Incoming connections must present an RCAN issued by this endpoint.
        let host = iroh_services::ClientHost::new(&endpoint);

        let mut router =
            Router::builder(endpoint.clone()).accept(iroh_services::CLIENT_HOST_ALPN, host);

        if let Some(home) = &self.roost {
            tracing::debug!("roost mode: checking for sshd on port {}", home.ssh_port);
            ssh::ensure_local_ssh_server_exists(home.ssh_port).await?;
            let handler = PigeonsProtocol::new(home.ssh_port);
            router = router.accept(PigeonsProtocol::ALPN, handler);
            tracing::info!(
                "roost accepting connections on ALPN {:?}",
                std::str::from_utf8(PigeonsProtocol::ALPN)
            );
        }

        for (alpn, handler) in self.extra_protocols {
            tracing::info!(
                "registering extra protocol on ALPN {:?}",
                std::str::from_utf8(&alpn)
            );
            router = router.accept(alpn, handler);
        }

        let router = router.spawn();
        tracing::debug!("router spawned");

        Ok(Tunnel {
            router,
            isvc_client: Some(client),
        })
    }
}

#[derive(Debug)]
pub struct Tunnel {
    router: Router,
    #[allow(dead_code)]
    isvc_client: Option<iroh_services::Client>,
}

impl Tunnel {
    pub fn builder_ephemeral() -> TunnelBuilder {
        TunnelBuilder::default()
    }

    pub fn builder_from_ssh_dir(ssh_dir: PathBuf) -> Result<TunnelBuilder> {
        let secret_key = dot_ssh_secret_key(ssh_dir)?;
        Ok(TunnelBuilder::new(secret_key))
    }

    pub async fn fly(&self, remote: EndpointId) -> Result<()> {
        let bind_addr = format!("127.0.0.1:{}", 0);
        let listener = TcpListener::bind(&bind_addr).await?;
        tracing::info!("fly: listening on {}", listener.local_addr()?);
        prepare_pigeon(self.endpoint().clone(), listener, remote).await
    }

    /// Bridge stdin/stdout directly to a remote roost via iroh.
    /// Designed for use as an SSH ProxyCommand:
    ///   ProxyCommand pigeons fly --stdio <endpoint_id>
    pub async fn fly_stdio(&self, remote: EndpointId) -> Result<()> {
        tracing::debug!("fly_stdio: connecting to {remote}");
        let conn = self
            .endpoint()
            .connect(remote, PigeonsProtocol::ALPN)
            .await?;
        tracing::debug!("fly_stdio: connected, opening bidirectional stream");
        let (mut iroh_send, mut iroh_recv) = conn.open_bi().await?;
        tracing::debug!("fly_stdio: bridging stdin/stdout");

        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();

        let stdin_to_iroh = copy_flush(&mut stdin, &mut iroh_send);
        let iroh_to_stdout = copy_flush(&mut iroh_recv, &mut stdout);

        tokio::select! {
            result = stdin_to_iroh => { result?; }
            result = iroh_to_stdout => { result?; }
        }

        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.router.shutdown().await.context("shutting down router")
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }
}

async fn prepare_pigeon(
    endpoint: Endpoint,
    listener: TcpListener,
    remote: EndpointId,
) -> Result<()> {
    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer_addr)) => {
                tracing::info!("pigeon departing from {peer_addr}");
                let endpoint = endpoint.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_connection(tcp_stream, &endpoint, remote).await {
                        tracing::error!("pigeon lost in transit: {e}");
                    }
                });
            }
            Err(err) => {
                tracing::error!("failed to accept connection: {err}");
                return Err(anyhow!(err));
            }
        }
    }
}

/// takes a TCP stream & adds it
async fn bridge_connection(
    tcp_stream: tokio::net::TcpStream,
    endpoint: &Endpoint,
    remote_id: EndpointId,
) -> anyhow::Result<()> {
    tcp_stream.set_nodelay(true)?;
    tracing::debug!("bridge_connection: connecting to {remote_id}");
    let conn = endpoint.connect(remote_id, PigeonsProtocol::ALPN).await?;
    tracing::debug!("bridge_connection: connected, opening bi stream");
    let (mut iroh_send, mut iroh_recv) = conn.open_bi().await?;
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let tcp_to_iroh = copy_flush(&mut tcp_read, &mut iroh_send);
    let iroh_to_tcp = copy_flush(&mut iroh_recv, &mut tcp_write);

    tokio::select! {
        result = tcp_to_iroh => {
            let _ = result;
        }
        result = iroh_to_tcp => {
            let _ = result;
        }
    }

    Ok(())
}

/// Copy data from reader to writer, flushing after every write.
/// Unlike `tokio::io::copy` (which buffers 8KB before flushing),
/// this ensures interactive data like SSH keystrokes are forwarded
/// immediately.
pub(crate) async fn copy_flush<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        total += n as u64;
    }
}
