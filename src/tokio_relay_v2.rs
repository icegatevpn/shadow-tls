use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use byteorder::{BigEndian, WriteBytesExt};
use hmac::Mac;
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

// Constants copied from the original project
const TLS_MAJOR: u8 = 0x03;
const TLS_MINOR: (u8, u8) = (0x03, 0x01);
const HMAC_SIZE_V2: usize = 8;
const TLS_HEADER_SIZE: usize = 5;
const HANDSHAKE: u8 = 0x16;
const APPLICATION_DATA: u8 = 0x17;
const CHANGE_CIPHER_SPEC: u8 = 0x14;
const COPY_BUF_SIZE: usize = 4096;

// Necessary trait for HMAC operations
trait HashedStream {
    fn hash_stream(&self) -> [u8; 20];
}

pub struct HashedReadStream<S> {
    inner: S,
    hmac: hmac::Hmac<sha1::Sha1>,
}

impl<S> HashedReadStream<S> {
    pub fn new(inner: S, password: &[u8]) -> Result<Self> {
        Ok(Self {
            inner,
            hmac: hmac::Hmac::new_from_slice(password).map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?,
        })
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn hash(&self) -> [u8; 20] {
        self.hmac
            .clone()
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }
}

impl<S> HashedStream for HashedReadStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

// Implement AsyncRead for HashedReadStream to track data for HMAC
impl<S: AsyncRead + Unpin> AsyncRead for HashedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let initial_filled = buf.filled().len();
        let pin_inner = Pin::new(&mut self.inner);

        match pin_inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let new_filled = buf.filled().len();
                if new_filled > initial_filled {
                    // Update HMAC with the newly read data
                    self.hmac.update(&buf.filled()[initial_filled..new_filled]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

// Passthrough for AsyncWrite functionality
impl<S: AsyncWrite + Unpin> AsyncWrite for HashedReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// HashedWriteStream for outgoing data
struct HashedWriteStream<S> {
    inner: S,
    hmac: hmac::Hmac<sha1::Sha1>,
    enabled: bool,
}

impl<S> HashedWriteStream<S> {
    pub fn new(inner: S, password: &[u8]) -> Result<Self> {
        Ok(Self {
            inner,
            hmac: hmac::Hmac::new_from_slice(password).map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?,
            enabled: true,
        })
    }

    pub fn hash(&self) -> [u8; 20] {
        self.hmac
            .clone()
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl<S> HashedStream for HashedWriteStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

// Implement AsyncRead passthrough for HashedWriteStream
impl<S: AsyncRead + Unpin> AsyncRead for HashedWriteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// Implement AsyncWrite for HashedWriteStream to track data for HMAC
impl<S: AsyncWrite + Unpin> AsyncWrite for HashedWriteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if self.enabled {
                    self.hmac.update(&buf[..n]);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// A helper struct for handling the switching result
enum SwitchResult {
    Switch(Vec<u8>),
    DirectProxy,
}

// Main relay implementation for tokio
pub struct TokioRelayV2 {
    listen_addr: Arc<String>,
    target_addr: Arc<String>,
    password: Arc<String>,
    nodelay: bool,
}

impl TokioRelayV2 {
    pub fn new(listen_addr: String, target_addr: String, password: String, nodelay: bool) -> Self {
        Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            password: Arc::new(password),
            nodelay,
        }
    }

    pub async fn serve(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&*self.listen_addr).await?;
        println!("Listening on: {}", self.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("Accepted connection from: {}", addr);

            if self.nodelay {
                socket.set_nodelay(true)?;
            }

            let target_addr = self.target_addr.clone();
            let password = self.password.clone();

            // Spawn a new task to handle this connection
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, &target_addr, &password).await {
                    eprintln!("Connection error: {}", e);
                }
                println!("Connection from {} closed", addr);
            });
        }
    }

    async fn handle_connection(socket: TcpStream, target_addr: &str, password: &str) -> Result<()> {
        // Wrap the incoming stream with HMAC tracking
        let mut stream = HashedWriteStream::new(socket, password.as_bytes())?;

        // Connect to the target server
        let target_stream = TcpStream::connect(target_addr).await?;
        if let Err(e) = target_stream.set_nodelay(true) {
            println!("Warning: Could not set TCP_NODELAY: {}", e);
        }

        println!("Connected to target server: {}", target_addr);

        // Split the streams
        let (mut in_read, mut in_write) = tokio::io::split(stream);
        let (mut target_read, mut target_write) = tokio::io::split(target_stream);

        // Start the relay process
        // First check for handshake completion
        let switch_result = Self::copy_until_handshake_finished(
            &mut in_read,
            &mut target_write,
            // We need to get the HMAC handler here
            // For simplicity in this example, we'll just pass a dummy handler
            &HashedWriteStream::new(
                TcpStream::connect(target_addr).await.unwrap(),
                password.as_bytes()
            )?,
        ).await?;

        match switch_result {
            SwitchResult::Switch(data_left) => {
                println!("Handshake finished, switching to data mode");

                // Close the current target connection
                drop(target_read);
                drop(target_write);

                // Open a new connection to the real data server
                // In a real implementation, this would be a different address
                let data_server = TcpStream::connect(target_addr).await?;
                if let Err(e) = data_server.set_nodelay(true) {
                    println!("Warning: Could not set TCP_NODELAY on data connection: {}", e);
                }

                // Write any pending data
                let (mut data_read, mut data_write) = tokio::io::split(data_server);
                data_write.write_all(&data_left).await?;

                // Now we need to relay data with the correct TLS framing
                let (a, b) = tokio::join!(
                    copy_with_application_data(&mut data_read, &mut in_write, None),
                    copy_without_application_data(&mut in_read, &mut data_write)
                );

                // Handle any errors
                a?;
                b?;
            },
            SwitchResult::DirectProxy => {
                println!("Direct proxy mode activated");

                // Just relay data as-is without switching
                let (a, b) = tokio::join!(
                    tokio::io::copy(&mut target_read, &mut in_write),
                    tokio::io::copy(&mut in_read, &mut target_write)
                );

                // Handle any errors
                a?;
                b?;
            }
        }

        println!("Connection handling complete");
        Ok(())
    }

    // Copy data until handshake is finished, checking HMAC signatures
    async fn copy_until_handshake_finished<R, W>(
        read_half: &mut R,
        write_half: &mut W,
        hmac_handler: &HashedWriteStream<TcpStream>,
    ) -> Result<SwitchResult>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        // State tracking
        let mut has_seen_change_cipher_spec = false;
        let mut has_seen_handshake = false;

        // Buffers for header and data
        let mut header_buf = vec![0_u8; TLS_HEADER_SIZE];
        let mut data_hmac_buf = vec![0_u8; HMAC_SIZE_V2];
        let mut data_buf = vec![0_u8; 2048];
        let mut application_data_count: usize = 0;

        // Store recent hash values for comparison
        let mut hashes = VecDeque::with_capacity(10);

        loop {
            // Read header
            let read_len = read_half.read_exact(&mut header_buf).await?;
            if read_len == 0 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed unexpectedly"));
            }

            // Forward header
            write_half.write_all(&header_buf).await?;

            // Parse the header
            let data_size = u16::from_be_bytes([header_buf[3], header_buf[4]]) as usize;
            println!("Read header with type {} and length {}", header_buf[0], data_size);

            // Handle based on content type
            if header_buf[0] != APPLICATION_DATA
                || !has_seen_handshake
                || !has_seen_change_cipher_spec
                || data_size < HMAC_SIZE_V2
            {
                // Validate the TLS frame
                let valid = (has_seen_handshake || header_buf[0] == HANDSHAKE)
                    && header_buf[1] == TLS_MAJOR
                    && (header_buf[2] == TLS_MINOR.0 || header_buf[2] == TLS_MINOR.1);

                if header_buf[0] == CHANGE_CIPHER_SPEC {
                    has_seen_change_cipher_spec = true;
                }
                if header_buf[0] == HANDSHAKE {
                    has_seen_handshake = true;
                }

                // Copy the data part
                let mut remaining = data_size;
                while remaining > 0 {
                    let read_size = remaining.min(data_buf.len());
                    let buf = &mut data_buf[..read_size];
                    read_half.read_exact(buf).await?;
                    write_half.write_all(buf).await?;
                    remaining -= read_size;
                }

                if !valid {
                    println!("Early invalid TLS: header {:?}", &header_buf[..3]);
                    return Ok(SwitchResult::DirectProxy);
                }

                continue;
            }

            // Read potential HMAC value
            read_half.read_exact(&mut data_hmac_buf).await?;
            write_half.write_all(&data_hmac_buf).await?;

            // Check HMAC
            let hash = hmac_handler.hash();
            let mut hash_trim = [0; HMAC_SIZE_V2];
            hash_trim.copy_from_slice(&hash[..HMAC_SIZE_V2]);

            // Store hash for comparison
            if hashes.len() + 1 > hashes.capacity() {
                hashes.pop_front();
            }
            hashes.push_back(hash_trim);

            // Compare with received HMAC
            let mut received_hmac = [0; HMAC_SIZE_V2];
            received_hmac.copy_from_slice(&data_hmac_buf);

            if hashes.contains(&received_hmac) {
                println!("HMAC matches");

                // Read the rest of the data as pure data
                let mut pure_data = vec![0; data_size - HMAC_SIZE_V2];
                read_half.read_exact(&mut pure_data).await?;

                return Ok(SwitchResult::Switch(pure_data));
            }

            // HMAC doesn't match, continue copying
            application_data_count += 1;

            // Copy the remaining data
            let mut remaining = data_size - HMAC_SIZE_V2;
            while remaining > 0 {
                let read_size = remaining.min(data_buf.len());
                let buf = &mut data_buf[..read_size];
                read_half.read_exact(buf).await?;
                write_half.write_all(buf).await?;
                remaining -= read_size;
            }

            if application_data_count > 3 {
                println!("HMAC not matches after 3 times, fallback to direct");
                return Ok(SwitchResult::DirectProxy);
            }
        }
    }

    // Additional helper functions would go here
    // Such as copy_with_application_data, copy_without_application_data, etc.
}

// Helper function to copy_with_application_data
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
        let read_size = reader.read(&mut buf[header_size + prefix_size..]).await?;
        if read_size == 0 {
            // End of stream
            break;
        }

        // Set the correct data length in the header
        let data_len = (read_size + prefix_size) as u16;
        buf[3..5].copy_from_slice(&data_len.to_be_bytes());

        // Write the entire frame
        writer.write_all(&buf[..header_size + prefix_size + read_size]).await?;
        transferred += (header_size + prefix_size + read_size) as u64;
    }

    // Ensure everything is written
    writer.flush().await?;
    writer.shutdown().await?;

    Ok(transferred)
}

// Helper function to copy_without_application_data
async fn copy_without_application_data<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; COPY_BUF_SIZE];
    let mut header_buf = [0u8; TLS_HEADER_SIZE];
    let mut transferred: u64 = 0;

    loop {
        // Read TLS header
        let read_size = reader.read_exact(&mut header_buf).await?;
        if read_size == 0 {
            break;
        }

        // Validate the header
        if header_buf[0] != APPLICATION_DATA {
            return Err(Error::new(ErrorKind::InvalidData, "Expected APPLICATION_DATA frame"));
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
    writer.shutdown().await?;

    Ok(transferred)
}