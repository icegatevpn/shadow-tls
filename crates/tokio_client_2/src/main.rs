// Improved shadow-tls client implementation with better TLS record handling

mod buf;
mod io;
mod driver;
mod net;
mod utils;
mod fs;
mod macros;

use std::io as std_io;
use std_io::{ErrorKind};

use std::{
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    spawn,
    time::timeout,
};
use bytes::{BytesMut, BufMut};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio_rustls::{rustls::{
    Certificate, ClientConfig, Error as TLSError,
    ServerName, client::ServerCertVerifier
}, TlsConnector};
use rand::seq::SliceRandom;
use std::pin::Pin;
use std::task::{Context, Poll};
use clap::Parser;
use tracing::{debug, error, warn, info};
use anyhow::{Result, Context as AnyhowContext, anyhow};
use rustls_fork_shadow_tls::{OwnedTrustAnchor, RootCertStore, ClientConfig as ShadowClientConfig};
use shadowTlsTokioLib::BufResult;

/// CLI arguments
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Local address to listen on (e.g., 127.0.0.1:1080)
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: String,
    /// Shadow-TLS server address (host:port)
    #[arg(long)]
    server: String,
    /// Comma-separated list of SNI names to use
    #[arg(long)]
    sni: String,
    /// Pre-shared password
    #[arg(long)]
    password: String,
}

impl Cli {
    fn test_config() -> Cli {
        Cli {
            listen: "127.0.0.1:666".to_string(),
            server: "45.86.229.176:4433".to_string(), // Use your server address here
            sni: "captive.apple.com".to_string(),
            password: "pwd1".to_string(),
        }
    }
}

// Constants from the Shadow TLS protocol
const TLS_HEADER_SIZE: usize = 5;
const HMAC_SIZE_V2: usize = 8;
const APPLICATION_DATA: u8 = 0x17;  // TLS Application Data type
const HANDSHAKE: u8 = 0x16;         // TLS Handshake type
const CHANGE_CIPHER_SPEC: u8 = 0x14; // TLS ChangeCipherSpec type
const ALERT: u8 = 0x15;             // TLS Alert type
const COPY_BUF_SIZE: usize = 16384; // Increased buffer size for better performance
const MAX_TLS_RECORD_SIZE: usize = 16384 + 2048; // Max TLS record size plus some margin
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60); // Connection timeout

// A certificate verifier that accepts any certificate
struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, TLSError> {
        // Return OK for any certificate
        Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let cli = Cli::test_config();
    info!("Starting Shadow TLS client with: {:?}", cli);

    let client = ShadowTlsClient::new(cli)?;
    client.serve().await
}

#[derive(Clone)]
struct ShadowTlsClient {
    listen_addr: Arc<String>,
    server_addr: Arc<String>,
    tls_connector: TlsConnector,
    snis: Arc<Vec<String>>,
    password: Arc<Vec<u8>>,
}

impl ShadowTlsClient {
    /// Convert a rustls_fork_shadow_tls client configuration for use with tokio_rustls
    pub fn convert_to_tokio_rustls() -> Result<tokio_rustls::TlsConnector> {
        // Create a new root store and populate it
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

        // Add the Mozilla root certificates
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject.as_ref(),
                    ta.subject_public_key_info.as_ref(),
                    ta.name_constraints.as_ref().map(|n| n.as_ref()),
                )
            })
        );

        // Create a new ClientConfig with the root store
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .context("Failed to set protocol versions")?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Convert to TlsConnector
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        Ok(connector)
    }

    fn new(cli: Cli) -> Result<Self> {
        // Build root cert store
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject.as_ref(),
                    ta.subject_public_key_info.as_ref(),
                    ta.name_constraints.as_ref().map(|n| n.as_ref()),
                )
            }),
        );

        // Create TLS config
        let mut tls_config = rustls_fork_shadow_tls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // IMPORTANT: Disable certificate verification
        // config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification {}));
        let tls_connector = ShadowTlsClient::convert_to_tokio_rustls()?;

        // let tls_connector = TlsConnector::from(Arc::new(tls_config));
        let snis = cli.sni.split(',').map(|s| s.trim().to_string()).collect();

        Ok(Self {
            listen_addr: Arc::new(cli.listen),
            server_addr: Arc::new(cli.server),
            tls_connector,
            snis: Arc::new(snis),
            password: Arc::new(cli.password.into_bytes()),
        })
    }

    async fn serve(&self) -> Result<()> {
        let listener = TcpListener::bind(&*self.listen_addr).await?;
        info!("TC2: Listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((client_stream, peer_addr)) => {
                    info!("TC2: Accepted connection from {}", peer_addr);

                    // Set TCP_NODELAY for better performance
                    if let Err(e) = client_stream.set_nodelay(true) {
                        debug!("Failed to set TCP_NODELAY: {}", e);
                    }

                    let client = self.clone();
                    spawn(async move {
                        if let Err(e) = client.handle_connection(client_stream).await {
                            error!("Connection error from {}: {:?}", peer_addr, e);
                        } else {
                            info!("Connection from {} completed successfully", peer_addr);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    // Add a small delay to avoid CPU spinning on accept errors
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_connection(&self, client_stream: TcpStream) -> Result<()> {
        debug!("Starting Shadow TLS handshake with server");

        // Set a timeout for the entire connection handling
        match timeout(CONNECTION_TIMEOUT, self._handle_connection(client_stream)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!("Connection handling timed out after {:?}", CONNECTION_TIMEOUT))
        }
    }

    async fn _handle_connection(&self, client_stream: TcpStream) -> Result<()> {
        // First check if this is an HTTP CONNECT proxy request
        let mut peek_buf = [0u8; 8];
        let client_stream = match client_stream.peek(&mut peek_buf).await {
            Ok(n) if n >= 7 => {
                // Check if it's an HTTP CONNECT request
                let tmp_buf = &peek_buf[..7];
                if tmp_buf == b"CONNECT" || tmp_buf == b"connect" || tmp_buf == b"Connect" {
                    self.handle_http_connect(client_stream).await?
                } else {
                    client_stream
                }
            },
            _ => client_stream,
        };

        // Connect and perform shadow TLS handshake
        let (server_stream, hash) = self.connect_v2().await?;

        // Extract 8-byte tag from the HMAC
        let mut hash_8b = [0u8; HMAC_SIZE_V2];
        hash_8b.copy_from_slice(&hash[..HMAC_SIZE_V2]);

        debug!("Handshake complete, starting relay with HMAC tag: {:02x?}", hash_8b);

        // Handle bidirectional relay with proper error handling
        match self.relay_connections(client_stream, server_stream, &hash_8b).await {
            Ok((client_bytes, server_bytes)) => {
                info!("Relay completed. Sent {} bytes, received {} bytes",
                      client_bytes, server_bytes);
                Ok(())
            }
            Err(e) => {
                // Log and return the error
                Err(anyhow!("Relay error: {}", e))
            }
        }
    }

    // Handle HTTP CONNECT method from proxy clients
    async fn handle_http_connect(&self, mut stream: TcpStream) -> Result<TcpStream> {
        debug!("Handling HTTP CONNECT request");

        let mut buf = BytesMut::with_capacity(4096);
        let mut headers_complete = false;
        let mut host = String::new();

        while !headers_complete {
            let mut temp = [0u8; 1024];
            let n = match stream.read(&mut temp).await {
                Ok(0) => return Err(anyhow!("Client closed connection during CONNECT")),
                Ok(n) => n,
                Err(e) => return Err(anyhow!("Error reading CONNECT request: {}", e)),
            };

            buf.put_slice(&temp[..n]);

            // Look for end of headers
            if buf.len() >= 4 {
                for i in 0..(buf.len() - 3) {
                    if &buf[i..i+4] == b"\r\n\r\n" {
                        headers_complete = true;
                        break;
                    }
                }
            }

            // Try to extract host for debugging
            if host.is_empty() {
                let req_str = String::from_utf8_lossy(&buf);
                if let Some(connect_line) = req_str.lines().next() {
                    if connect_line.starts_with("CONNECT ") {
                        let parts: Vec<&str> = connect_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            host = parts[1].to_string();
                            debug!("CONNECT request for host: {}", host);
                        }
                    }
                }
            }

            if buf.len() > 16384 {  // Safeguard against too large headers
                return Err(anyhow!("HTTP headers too large"));
            }
        }

        // Send 200 Connection Established response
        let response = "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await
            .context("Failed to send HTTP 200 response")?;
        debug!("Sent HTTP 200 Connection Established response for {}", host);

        Ok(stream)
    }

    async fn connect_v2(&self) -> Result<(TcpStream, [u8; 20])> {
        // Connect to the shadow TLS server
        debug!("Connecting to Shadow TLS server: {}", self.server_addr);
        let server_stream = TcpStream::connect(&*self.server_addr).await
            .context("Failed to connect to Shadow TLS server")?;

        // Enable TCP_NODELAY for better performance
        if let Err(e) = server_stream.set_nodelay(true) {
            debug!("Failed to set TCP_NODELAY on server connection: {}", e);
        }

        // Wrap server stream with HMAC calculator
        let mut hashed_stream = HashedStream::new(server_stream, &self.password)
            .context("Failed to create HMAC stream")?;

        // Choose a random SNI from our list
        let sni = {
            let mut rng = rand::thread_rng();
            self.snis.choose(&mut rng).unwrap().clone()
        };

        // Convert to a DNS name
        let server_name = ServerName::try_from(sni.as_str())
            .context("Invalid server name")?;

        info!("Using Server_name: {:?}", server_name);

        // Perform TLS handshake with timeout
        debug!("Starting TLS handshake");
        let tls_handshake = self.tls_connector.connect(server_name, &mut hashed_stream);

        let tls_stream = match timeout(Duration::from_secs(10), tls_handshake).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow!("TLS handshake failed: {}", e)),
            Err(_) => return Err(anyhow!("TLS handshake timed out")),
        };

        // We don't need the TLS stream, just wanted to complete the handshake
        drop(tls_stream);
        info!("TLS handshake completed successfully");

        // Extract the HMAC and the raw TCP stream
        let (server_stream, hmac) = hashed_stream.into_inner();
        info!("HMAC hash calculated: {:02x?}", &hmac[..HMAC_SIZE_V2]);

        Ok((server_stream, hmac))
    }

    // Bidirectional relay with proper error handling
    async fn relay_connections(
        &self,
        client_stream: TcpStream,
        server_stream: TcpStream,
        hash_8b: &[u8; HMAC_SIZE_V2]
    ) -> Result<(u64, u64)> {
        // Configure both streams with appropriate settings
        for stream in [&client_stream, &server_stream] {
            if let Err(e) = stream.set_nodelay(true) {
                debug!("Failed to set TCP_NODELAY: {}", e);
            }
        }

        // Split streams
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut server_read, mut server_write) = tokio::io::split(server_stream);

        // Use a proper session filter
        let hash_clone = hash_8b.clone();
        let client_to_server = tokio::spawn(async move {
            copy_client_to_server(&mut client_read, &mut server_write, &hash_clone).await
        });

        let server_to_client = tokio::spawn(async move {
            copy_server_to_client(&mut server_read, &mut client_write).await
        });

        // Wait for both tasks to complete
        let (client_result, server_result) = tokio::join!(
            client_to_server,
            server_to_client
        );

        // Handle potential errors in spawned tasks
        let client_bytes = match client_result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(anyhow!("Client-to-server error: {}", e)),
            Err(e) => return Err(anyhow!("Client-to-server task failed: {}", e)),
        };

        let server_bytes = match server_result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(anyhow!("Server-to-client error: {}", e)),
            Err(e) => return Err(anyhow!("Server-to-client task failed: {}", e)),
        };

        Ok((client_bytes, server_bytes))
    }
}

// Stream wrapper that calculates HMAC during TLS handshake
struct HashedStream {
    inner: TcpStream,
    mac: Hmac<Sha1>,
}

impl HashedStream {
    fn new(stream: TcpStream, key: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: stream,
            mac: Hmac::<Sha1>::new_from_slice(key)
                .map_err(|_| std_io::Error::new(ErrorKind::InvalidInput, "Invalid key length"))?,
        })
    }

    fn into_inner(self) -> (TcpStream, [u8; 20]) {
        let result = self.mac.finalize().into_bytes();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&result[..20]);
        (self.inner, hash)
    }
}

impl AsyncRead for HashedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std_io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Calculate how many bytes were read
                let filled_after = buf.filled().len();
                let new_bytes = &buf.filled()[filled_before..filled_after];

                // Only update HMAC if we read some bytes
                if !new_bytes.is_empty() {
                    self.mac.update(new_bytes);
                    debug!("Read {} bytes from server for HMAC calculation", new_bytes.len());
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for HashedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std_io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std_io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std_io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Client to server - wrap data in TLS Application Data records with the HMAC tag
async fn copy_client_to_server(
    client: &mut (impl AsyncRead + Unpin),
    server: &mut (impl AsyncWrite + Unpin),
    tag: &[u8; HMAC_SIZE_V2],
) -> std_io::Result<u64> {
    let mut total_bytes = 0u64;

    // Preallocate a buffer for efficiency
    let mut buffer = BytesMut::with_capacity(COPY_BUF_SIZE + TLS_HEADER_SIZE + HMAC_SIZE_V2);

    // Setup the constant part of the TLS header
    let record_header = [
        APPLICATION_DATA,  // type
        0x03, 0x03,       // TLS 1.2 version
        0, 0,             // length placeholder
    ];

    loop {
        // Reset buffer for next read
        buffer.clear();
        buffer.reserve(COPY_BUF_SIZE + TLS_HEADER_SIZE + HMAC_SIZE_V2);

        // Make room for header and HMAC tag
        buffer.extend_from_slice(&record_header);
        buffer.extend_from_slice(tag);

        // Create a slice for reading directly after the header and tag
        let mut read_buf = vec![0u8; COPY_BUF_SIZE];

        // Read data from client
        let n = match client.read(&mut read_buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                if e.kind() == ErrorKind::ConnectionReset || e.kind() == ErrorKind::BrokenPipe {
                    debug!("Client connection reset or broken pipe, closing relay");
                    break;
                }
                return Err(e);
            }
        };

        // Add the data to our buffer
        buffer.extend_from_slice(&read_buf[..n]);

        // Update the length field in the header
        let total_len = HMAC_SIZE_V2 + n;
        let len_bytes = (total_len as u16).to_be_bytes();
        buffer[3] = len_bytes[0];
        buffer[4] = len_bytes[1];

        // Write the entire record to the server in one operation
        match server.write_all(&buffer).await {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == ErrorKind::ConnectionReset || e.kind() == ErrorKind::BrokenPipe {
                    debug!("Server connection reset or broken pipe");
                    break;
                }
                return Err(e);
            }
        }

        total_bytes += n as u64;
        debug!("Forwarded {} bytes from client to server", n);
    }

    // Try to shutdown gracefully, but don't fail if it doesn't work
    let _ = server.shutdown().await;
    debug!("Client-to-server relay finished, total: {} bytes", total_bytes);
    Ok(total_bytes)
}

// Server to client - extract Application Data payloads from TLS records
async fn copy_server_to_client(
    server: &mut (impl AsyncRead + Unpin),
    client: &mut (impl AsyncWrite + Unpin),
) -> std_io::Result<u64> {
    let mut total_bytes = 0u64;
    let mut header = [0u8; TLS_HEADER_SIZE];
    let mut buffer = BytesMut::with_capacity(MAX_TLS_RECORD_SIZE);

    loop {
        // Read TLS record header
        match server.read_exact(&mut header).await {
            Ok(_) => {},
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                debug!("Server EOF");
                break;
            },
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                debug!("Server connection reset");
                break;
            }
            Err(e) => return Err(e),
        }

        // Parse header
        let record_type = header[0];
        let record_version = (header[1], header[2]); // TLS version
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Validate header to avoid processing invalid records
        if record_len > MAX_TLS_RECORD_SIZE {
            warn!("Invalid TLS record length: {} exceeds maximum {}", record_len, MAX_TLS_RECORD_SIZE);
            continue;
        }

        // Make sure we have enough capacity and clean buffer
        buffer.clear();
        buffer.resize(record_len, 0);

        // Read record payload
        match server.read_exact(&mut buffer).await {
            Ok(_) => {},
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                warn!("Unexpected EOF while reading record payload");
                break;
            }
            Err(e) => return Err(e),
        }

        match record_type {
            APPLICATION_DATA => {
                // For application data, strip HMAC from the start if present
                let data_offset = if record_len > HMAC_SIZE_V2 &&
                    (record_version.0 == 0x03 && (record_version.1 == 0x03 || record_version.1 == 0x01)) {
                    HMAC_SIZE_V2
                } else {
                    0
                };

                if data_offset < record_len {
                    let data_len = record_len - data_offset;
                    match client.write_all(&buffer[data_offset..]).await {
                        Ok(_) => {
                            total_bytes += data_len as u64;
                            debug!("Forwarded {} bytes of application data to client", data_len);
                        }
                        Err(e) if e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionReset => {
                            debug!("Client connection closed while writing");
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            ALERT => {
                // Handle TLS alerts - they might indicate connection closure
                if buffer.len() >= 2 {
                    let alert_level = buffer[0];
                    let alert_desc = buffer[1];
                    debug!("Received TLS alert: level={}, desc={}", alert_level, alert_desc);

                    // Fatal alerts should close the connection
                    if alert_level == 2 { // fatal
                        break;
                    }
                }
            }
            // Skip other TLS record types
            _ => {
                debug!("Skipped {} bytes of record type {}", record_len, record_type);
            }
        }
    }

    // Try to shutdown gracefully, but don't fail if it doesn't work
    let _ = client.shutdown().await;
    debug!("Server-to-client relay finished, total: {} bytes", total_bytes);
    Ok(total_bytes)
}