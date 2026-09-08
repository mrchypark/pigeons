use std::{
    process::{Command, Stdio},
    time::Duration,
};

use iroh_pigeons::{RoostConfig, Tunnel};
use tokio::{net::TcpListener, sync::oneshot};

/// A ProxyCommand keeps its stdin open until it exits.  When the remote roost
/// disappears, that must not keep the `pigeons fly --stdio` process alive.
#[tokio::test]
async fn fly_stdio_exits_when_remote_closes_with_stdin_open() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = listener.local_addr().unwrap().port();
    let (connected_tx, connected_rx) = oneshot::channel();
    let ssh_service = tokio::spawn(async move {
        // Tunnel::build probes the port once.  Keep the actual roost
        // connection open so the client is blocked on stdin when it is closed.
        let (_probe, _) = listener.accept().await.unwrap();
        let (_connection, _) = listener.accept().await.unwrap();
        let _ = connected_tx.send(());
        std::future::pending::<()>().await;
    });

    let mut server_builder = Tunnel::builder_ephemeral().await.unwrap();
    server_builder.roost = Some(RoostConfig { ssh_port });
    let server = server_builder.build().await.unwrap();
    let remote_id = server.endpoint().id().to_string();
    let direct_address = server
        .endpoint()
        .addr()
        .ip_addrs()
        .next()
        .expect("local endpoint has a direct address")
        .to_string();

    let key_dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pigeons"))
        .args([
            "fly",
            "--stdio",
            &remote_id,
            "--key-dir",
            key_dir.path().to_str().unwrap(),
            "--direct-address",
            &direct_address,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();

    let connected = tokio::time::timeout(Duration::from_secs(10), connected_rx).await;
    if !matches!(connected, Ok(Ok(()))) {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        ssh_service.abort();
        panic!("client did not reach the roost");
    }
    server.close().await.unwrap();

    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    drop(stdin);
    ssh_service.abort();
    if status.is_err() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("stdio process stayed alive after remote close");
    }
}
