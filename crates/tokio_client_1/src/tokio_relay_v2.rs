use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    sync::Arc,
};
use byteorder::{BigEndian, WriteBytesExt};
use hmac::{KeyInit, Mac};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tracing::error;

// Constants from the original project
const TLS_MAJOR: u8 = 0x03;
const TLS_MINOR: (u8, u8) = (0x03, 0x01);
const HMAC_SIZE_V2: usize = 8;
const TLS_HEADER_SIZE: usize = 5;
const HANDSHAKE: u8 = 0x16;
const APPLICATION_DATA: u8 = 0x17;
const CHANGE_CIPHER_SPEC: u8 = 0x14;
const ALERT: u8 = 0x15;
const HEARTBEAT: u8 = 0x18;
const COPY_BUF_SIZE: usize = 4096;

// A helper struct for handling the switching result
#[derive(Debug)]
enum SwitchResult {
    Switch(Vec<u8>),
    DirectProxy,
}

// Main relay implementation for tokio
#[derive(Clone)]
pub struct TokioShadowTlsV2Relay {
    listen_addr: String,
    target_addr: String, // Handshake server address
    data_addr: String,   // Data server address (real server)
    password: String,
    nodelay: bool,
}

impl TokioShadowTlsV2Relay {
    pub fn new(
        listen_addr: String,
        target_addr: String,
        data_addr: String,
        password: String,
        nodelay: bool,
    ) -> Self {
        Self {
            listen_addr,
            target_addr,
            data_addr,
            password,
            nodelay,
        }
    }

    // Handle HTTP CONNECT method from proxy clients like curl
    async fn handle_http_connect(client: &mut TcpStream) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        let mut bytes_read = 0;
        let mut headers_complete = false;

        // Read until we find \r\n\r\n which marks the end of HTTP headers
        while bytes_read < buf.len() {
            let n = client.read(&mut buf[bytes_read..]).await?;
            if n == 0 {
                tracing::error!("ERRRRRrrrrrr");
                // End of stream
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Client closed connection",
                ));
            }

            bytes_read += n;

            // Look for end of headers
            if bytes_read >= 4 && &buf[bytes_read - 4..bytes_read] == b"\r\n\r\n" {
                headers_complete = true;
                break;
            }
        }

        if !headers_complete {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "HTTP headers too long or malformed",
            ));
        }

        // Send back a 200 Connection Established response
        let response = "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";
        client.write_all(response.as_bytes()).await?;

        tracing::trace!("Sent HTTP 200 Connection Established response");
        Ok(())
    }

    async fn check_is_http_header(mut client_stream: &mut TcpStream) -> Result<()> {
        // First, handle proxy CONNECT if it's coming from a proxy client like curl
        let mut buffer = [0u8; 4096];
        let n = client_stream.peek(&mut buffer).await?;

        // Check if this looks like an HTTP CONNECT request
        let data = &buffer[..n];
        let is_connect = n > 8
            && (data.starts_with(b"CONNECT ")
                || data.starts_with(b"connect ")
                || data.starts_with(b"Connect "));

        if is_connect {
            tracing::trace!("Detected HTTP CONNECT request");
            Self::handle_http_connect(&mut client_stream).await?;
        }
        Ok(())
    }

    pub async fn serve(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.listen_addr).await?;
        tracing::debug!("Listening on: {}", self.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            tracing::debug!("Accepted connection from: {}", addr);

            if self.nodelay {
                socket.set_nodelay(true)?;
            }

            let target_addr = self.target_addr.clone();
            let data_addr = self.data_addr.clone();
            let password = self.password.clone();

            // Spawn a new task to handle this connection
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(socket, &target_addr, &data_addr, &password).await
                {
                    tracing::error!("Connection error: {}", e);
                }
                tracing::trace!("Connection from {} closed", addr);
            });
        }
    }

    async fn handle_connection(
        mut client_stream: TcpStream,
        target_addr: &str, // Sni fake handshake server
        data_addr: &str,   // shadowTLS Server
        password: &str,
    ) -> Result<()> {
        Self::check_is_http_header(&mut client_stream).await?;

        tracing::trace!("Handling connection to target: {}", target_addr);

        // Initialize HMAC calculator
        let mut hmac: hmac::Hmac<sha1::Sha1> = hmac::Hmac::new_from_slice(password.as_bytes())
            .map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?;

        // Connect to the handshake server
        let mut handshake_server = TcpStream::connect("captive.apple.com:443").await?;//TcpStream::connect(target_addr).await?;
        if let Ok(_) = handshake_server.set_nodelay(true) {} // Best effort

        tracing::trace!("Connected to handshake server: {}", target_addr);

        // Use the handshake detection function
        let result = Self::relay_until_handshake_finished(
            &mut client_stream,
            &mut handshake_server,
            &mut hmac,
        )
        .await?;

        match result {
            SwitchResult::Switch(data_left) => {
                tracing::trace!("Handshake finished, switching to data server");

                // Close the handshake server connection
                drop(handshake_server);

                // Connect to the real data server
                let mut data_server = TcpStream::connect(data_addr).await?;
                if let Ok(_) = data_server.set_nodelay(true) {}
                tracing::trace!("Connected to data server: {}", data_addr);

                // Send any leftover data to the data server
                if !data_left.is_empty() {
                    data_server.write_all(&data_left).await?;
                }

                // Now relay data with proper TLS application data framing
                Self::relay_data_with_framing(&mut client_stream, &mut data_server).await?;
            }
            SwitchResult::DirectProxy => {
                tracing::warn!("Direct proxy mode activated");
                Self::relay_bidirectional(&mut client_stream, &mut handshake_server).await?;
            }
        }

        tracing::trace!("Connection handling complete");
        Ok(())
    }

    fn match_byte(byte: u8) {
        match byte {
            HANDSHAKE => {
                tracing::trace!("Received HANDSHAKE");
            }
            APPLICATION_DATA => {
                tracing::trace!("Received APPLICATION_DATA");
            }
            CHANGE_CIPHER_SPEC => {
                tracing::trace!("Received CHANGE_CIPHER_SPEC");
            }
            ALERT => {
                tracing::trace!("Received ALERT");
            }
            HEARTBEAT => {
                tracing::trace!("Received HEARTBEAT");
            }
            _ => {
                tracing::trace!("Received UNKNOWN byte {:02X?}", byte);
            }
        }
    }

    // Copy data until handshake is finished, checking HMAC signatures
    async fn relay_until_handshake_finished(
        mut client: &mut TcpStream,
        mut server: &mut TcpStream, // handshake_server (fake sni address)
        hmac: &mut hmac::Hmac<sha1::Sha1>,
    ) -> Result<SwitchResult> {
        // State tracking
        let mut has_seen_change_cipher_spec = false;
        let mut has_seen_handshake = false;

        // Buffers for header and data
        let mut header_buf = [0_u8; TLS_HEADER_SIZE];
        let mut data_hmac_buf = [0_u8; HMAC_SIZE_V2];
        let mut data_buf = vec![0_u8; 8192]; // Larger buffer for handshake data
        let mut application_data_count: usize = 0;

        // Store recent hash values for comparison
        let mut hashes = VecDeque::with_capacity(10);

        // Make sockets non-blocking to handle bidirectional flows
        client.set_nodelay(true)?;
        server.set_nodelay(true)?;

        // We need to handle both directions of traffic using an approach
        // that doesn't try to share mutable references
        loop {
            // First, check if there's data from the server to forward to the client
            let mut server_header_buf = [0_u8; TLS_HEADER_SIZE];
            let server_has_data = match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                server.peek(&mut server_header_buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => true,
                _ => false,
            };

            if server_has_data {
                // Server has data to send to the client
                server.read_exact(&mut server_header_buf).await?;

                // Forward header to client
                client.write_all(&server_header_buf).await?;

                // Parse the header to get data size
                let data_size =
                    u16::from_be_bytes([server_header_buf[3], server_header_buf[4]]) as usize;
                let content_type = server_header_buf[0];
                Self::match_byte(content_type);

                tracing::trace!(
                    "Server sent record: type={}, size={}",
                    content_type,
                    data_size
                );

                // Read and forward the payload
                Self::copy_exactly(server, client, data_size, &mut data_buf).await?;
                client.flush().await?;

                // Continue to handle more data
                continue;
            }

            // Now check for client data - with a longer timeout if server had no data
            let client_has_data = match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client.peek(&mut header_buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => true,
                _ => false,
            };

            if !client_has_data {
                // No data from either side, small sleep to prevent CPU spinning
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                continue;
            }

            // Client has data - read the full header
            client.read_exact(&mut header_buf).await?;

            // Forward header to server immediately
            server.write_all(&header_buf).await?;
            server.flush().await?;

            // Parse the header
            let content_type = header_buf[0];
            let version_major = header_buf[1];
            let version_minor = header_buf[2];
            let data_size = u16::from_be_bytes([header_buf[3], header_buf[4]]) as usize;
            Self::match_byte(content_type);

            tracing::trace!(
                "Client sent record: type={}, size={}",
                content_type,
                data_size
            );

            // Check if this is a valid TLS record
            let valid_record = (has_seen_handshake || content_type == HANDSHAKE)
                && version_major == TLS_MAJOR
                && (version_minor == TLS_MINOR.0 || version_minor == TLS_MINOR.1);

            // Update state tracking
            if content_type == CHANGE_CIPHER_SPEC {
                has_seen_change_cipher_spec = true;
                tracing::trace!("Saw ChangeCipherSpec message");
            }
            if content_type == HANDSHAKE {
                has_seen_handshake = true;
                tracing::trace!("Saw Handshake message");
            }

            // Handle application data differently if all conditions are met
            if content_type == APPLICATION_DATA
                && has_seen_handshake
                && has_seen_change_cipher_spec
                && data_size >= HMAC_SIZE_V2
            {
                // First read the potential HMAC value
                client.read_exact(&mut data_hmac_buf).await?;
                server.write_all(&data_hmac_buf).await?;
                server.flush().await?;

                // Calculate our expected HMAC
                let hash = hmac.clone().finalize().into_bytes();
                let mut hash_trim = [0; HMAC_SIZE_V2];
                hash_trim.copy_from_slice(&hash[..HMAC_SIZE_V2]);

                tracing::trace!(
                    "Expected HMAC: {:02x?}, Received: {:02x?}",
                    hash_trim,
                    data_hmac_buf
                );

                // Store hash for comparison
                if hashes.len() + 1 > hashes.capacity() {
                    hashes.pop_front();
                }
                hashes.push_back(hash_trim);

                // See if this matches any of our calculated HMACs
                let current_hmac_matches = hash_trim == data_hmac_buf;
                let any_hmac_matches = hashes.iter().any(|h| h == &data_hmac_buf);

                if current_hmac_matches || any_hmac_matches {
                    tracing::trace!("HMAC matches! Switching to data mode");

                    // Read the rest of this frame as pure data to forward to the real server
                    let mut pure_data = vec![0; data_size - HMAC_SIZE_V2];
                    client.read_exact(&mut pure_data).await?;

                    return Ok(SwitchResult::Switch(pure_data));
                }

                // HMAC doesn't match, continue proxy operation
                application_data_count += 1;
                tracing::trace!("HMAC didn't match, count now: {}", application_data_count);

                // Copy remaining data of this record
                let remaining = data_size - HMAC_SIZE_V2;
                Self::copy_exactly(client, server, remaining, &mut data_buf).await?;
                server.flush().await?;

                if application_data_count > 3 {
                    tracing::trace!(
                        "HMAC didn't match after 3 application data records, using direct proxy"
                    );
                    return Ok(SwitchResult::DirectProxy);
                }
            } else {
                // For all other record types, just copy the data through
                if content_type == HANDSHAKE && data_size > 0 {
                    // For handshake messages, update our HMAC calculation
                    let mut handshake_data = vec![0u8; data_size];
                    client.read_exact(&mut handshake_data).await?;

                    // Update the HMAC with handshake data
                    hmac.update(&handshake_data);
                    tracing::trace!("Updated HMAC with {} bytes of handshake data", data_size);

                    // Forward the data to the server
                    server.write_all(&handshake_data).await?;
                    server.flush().await?;
                } else {
                    // For other types, just copy through
                    Self::copy_exactly(client, server, data_size, &mut data_buf).await?;
                    server.flush().await?;
                }

                // If we see an invalid TLS record, switch to direct proxy mode
                if !valid_record {
                    tracing::trace!("Invalid TLS record detected, switching to direct proxy");
                    return Ok(SwitchResult::DirectProxy);
                }
            }
        }
    }

    // Helper to copy exactly N bytes from source to destination
    async fn copy_exactly(
        source: &mut TcpStream,
        destination: &mut TcpStream,
        mut bytes_to_copy: usize,
        buffer: &mut [u8],
    ) -> Result<()> {
        while bytes_to_copy > 0 {
            let read_size = bytes_to_copy.min(buffer.len());
            let buf = &mut buffer[..read_size];

            source.read_exact(buf).await?;
            destination.write_all(buf).await?;

            bytes_to_copy -= read_size;
        }
        Ok(())
    }

    // Simple bidirectional relay
    async fn relay_bidirectional(client: &mut TcpStream, server: &mut TcpStream) -> Result<()> {
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = server.split();

        let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
        let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

        let (res1, res2) = tokio::join!(client_to_server, server_to_client);
        res1?;
        res2?;

        Ok(())
    }

    // Relay with proper application data framing
    async fn relay_data_with_framing(
        client: &mut TcpStream,
        data_server: &mut TcpStream,
    ) -> Result<()> {
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = data_server.split();

        // Create tasks for both directions
        let client_to_server = async {
            Self::copy_without_application_data(&mut client_read, &mut server_write).await
        };

        let server_to_client = async {
            Self::copy_with_application_data(&mut server_read, &mut client_write, None).await
        };

        // Run both tasks concurrently
        let (res1, res2) = tokio::join!(client_to_server, server_to_client);
        res1?;
        res2?;

        Ok(())
    }

    // Helper function to copy data with TLS application data framing
    async fn copy_with_application_data<R, W>(
        reader: &mut R,
        writer: &mut W,
        prefix: Option<&[u8]>,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0; COPY_BUF_SIZE];
        buf[0] = APPLICATION_DATA;
        buf[1] = TLS_MAJOR;
        buf[2] = TLS_MINOR.0;

        // Apply prefix if provided
        let header_size = TLS_HEADER_SIZE;
        let prefix_size = prefix.map_or(0, |p| p.len());
        if let Some(p) = prefix {
            buf[header_size..header_size + prefix_size].copy_from_slice(p);
        }

        let mut transferred: u64 = 0;
        loop {
            // Read data into buffer after the header (and prefix if present)
            let read_size = match reader.read(&mut buf[header_size + prefix_size..]).await {
                Ok(0) => break, // End of stream
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            // Set the correct data length in the header
            let data_len = (read_size + prefix_size) as u16;
            buf[3..5].copy_from_slice(&data_len.to_be_bytes());

            // Write the entire frame
            writer
                .write_all(&buf[..header_size + prefix_size + read_size])
                .await?;
            transferred += (header_size + prefix_size + read_size) as u64;
        }

        // Ensure everything is written
        writer.flush().await?;

        Ok(transferred)
    }

    // Helper function to extract data from TLS application data frames
    async fn copy_without_application_data<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0; COPY_BUF_SIZE];
        let mut header_buf = [0u8; TLS_HEADER_SIZE];
        let mut transferred: u64 = 0;

        loop {
            // Read TLS header
            match reader.read_exact(&mut header_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            // Validate the header
            if header_buf[0] != APPLICATION_DATA {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Expected APPLICATION_DATA frame",
                ));
            }

            // Extract data length
            let data_size = u16::from_be_bytes([header_buf[3], header_buf[4]]) as usize;

            // Read and forward the data payload
            let mut remaining = data_size;
            while remaining > 0 {
                let read_size = remaining.min(buf.len());
                reader.read_exact(&mut buf[..read_size]).await?;
                writer.write_all(&buf[..read_size]).await?;
                remaining -= read_size;
                transferred += read_size as u64;
            }
        }

        writer.flush().await?;

        Ok(transferred)
    }
}
