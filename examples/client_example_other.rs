use std::{error::Error, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use rustls_fork_shadow_tls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls_fork_shadow_tls::TlsConnector;

// Import the TokioRelayV2 from your crate
// use shadow_tls_tokio::TokioRelayV2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set up logging
    env_logger::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <listen_addr> <server_addr> <tls_name> <password>", args[0]);
        eprintln!("Example: {} 127.0.0.1:1080 example.com:443 captive.apple.com password123", args[0]);
        std::process::exit(1);
    }

    let listen_addr = &args[1];
    let server_addr = &args[2];
    let tls_name = &args[3];
    let password = &args[4];

    println!("Starting Shadow-TLS client with tokio:");
    println!("Listening on: {}", listen_addr);
    println!("Connecting to: {}", server_addr);
    println!("Using TLS name: {}", tls_name);

    // Create and run the relay
    let relay = TokioRelayV2::new(
        listen_addr.to_string(),
        server_addr.to_string(),
        password.to_string(),
        true, // Enable TCP_NODELAY
    );

    // Start serving connections
    relay.serve().await?;

    Ok(())
}

// This function shows how you might implement a TLS connection
// with the Tokio runtime for the client side
async fn connect_tls_with_tokio(
    target_addr: &str,
    tls_name: &str,
    password: &[u8],
) -> Result<(TcpStream, [u8; 20]), Box<dyn Error>> {
    // Set up TLS configuration
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|n| n.as_ref()),
        )
    }));

    let tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect to the server
    let tcp_stream = TcpStream::connect(target_addr).await?;
    tcp_stream.set_nodelay(true)?;

    // Wrap the TCP stream with HMAC tracking
    let hashed_stream = HashedReadStream::new(tcp_stream, password)?;

    // Convert TLS name to ServerName
    let server_name = ServerName::try_from(tls_name)
        .map_err(|_| "Invalid DNS name")?;

    // Perform TLS handshake
    let tls_stream = connector.connect(server_name, hashed_stream).await?;

    // Extract components and hash
    let (io, _session) = tls_stream.into_parts();
    let hash = io.hash();
    let stream = io.into_inner();

    println!("TLS handshake completed, HMAC: {:?}", hash);

    Ok((stream, hash))
}