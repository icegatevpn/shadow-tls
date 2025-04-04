use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rustls_fork_shadow_tls::{
    ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection, ServerName //, Session
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
// Add the ready! macro if not available
#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pin_project! {
    /// TLS stream using rustls-fork-shadow-tls.
    /// This adapts the rustls API to work with tokio's asynchronous IO.
    pub struct TlsStream<IO, C> {
        #[pin]
        io: IO,
        session: C,
    }
}

impl<IO, C> TlsStream<IO, C> {
    pub fn new(io: IO, session: C) -> Self {
        Self { io, session }
    }

    pub fn get_ref(&self) -> (&IO, &C) {
        (&self.io, &self.session)
    }

    pub fn get_mut(&mut self) -> (&mut IO, &mut C) {
        (&mut self.io, &mut self.session)
    }

    pub fn into_parts(self) -> (IO, C) {
        (self.io, self.session)
    }
}

impl<IO, C> TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Session,
{
    async fn process_new_packets(&mut self) -> Result<()> {
        match self.session.process_new_packets() {
            Ok(_) => Ok(()),
            Err(err) => {
                // Map rustls error to io error
                Err(Error::new(ErrorKind::Other, format!("TLS error: {:?}", err)))
            }
        }
    }
}

/// ClientTlsStream using rustls-fork-shadow-tls
pub type ClientTlsStream<IO> = TlsStream<IO, ClientConnection>;

/// ServerTlsStream using rustls-fork-shadow-tls
pub type ServerTlsStream<IO> = TlsStream<IO, ServerConnection>;

impl<IO, C> AsyncRead for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Session,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.project();
        let mut io = this.io;
        let session = this.session;

        // First, check if there's unprocessed data in the session
        if let Some(mut reader) = session.reader() {
            let slice = buf.initialize_unfilled();
            match reader.read(slice) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                    // Need more data, continue to read from IO
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        // Read from the IO and feed the session
        ready!(io_loop(&mut io, session, cx))?;

        // Now try again to read from the session
        if let Some(mut reader) = session.reader() {
            let slice = buf.initialize_unfilled();
            match reader.read(slice) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                    // No data available yet
                    Poll::Ready(Ok(()))
                }
                Err(err) => Poll::Ready(Err(err)),
            }
        } else {
            // Session has no data but isn't blocking - probably closed
            Poll::Ready(Ok(()))
        }
    }
}

impl<IO, C> AsyncWrite for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Session,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.project();
        let mut io = this.io;
        let session = this.session;

        // Write the data to the session
        match session.writer().write(buf) {
            Ok(n) => {
                // Now we need to flush the session to the underlying IO
                ready!(io_loop(&mut io, session, cx))?;
                Poll::Ready(Ok(n))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.project();
        let mut io = this.io;
        let session = this.session;

        session.writer().flush()?;
        ready!(io_loop(&mut io, session, cx))?;

        Pin::new(&mut io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.as_mut().project();
        let mut io = this.io;
        let session = this.session;

        // Start clean shutdown if not already started
        if !session.is_handshaking() {
            session.send_close_notify();
        }

        // Flush any remaining data
        ready!(io_loop(&mut io, session, cx))?;

        // Complete the shutdown
        Pin::new(&mut io).poll_shutdown(cx)
    }
}

/// Helper function for the TLS IO processing loop
fn io_loop<IO, C>(
    io: &mut IO,
    session: &mut C,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Session,
{
    let mut made_progress = true;

    // Loop until no more progress can be made
    while made_progress {
        made_progress = false;

        // Write TLS data to the IO if available
        if session.wants_write() {
            let mut tmp = [0u8; 4096];

            match session.write_tls(&mut tmp.as_mut()) {
                Ok(n) => {
                    if n > 0 {
                        made_progress = true;
                        match Pin::new(io).poll_write(cx, &tmp[..n]) {
                            Poll::Ready(Ok(written)) => {
                                if written != n {
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::WriteZero,
                                        "failed to write complete TLS frame",
                                    )));
                                }
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                Err(err) => return Poll::Ready(Err(Error::new(ErrorKind::Other, err))),
            }
        }

        // Read from IO into the TLS session if needed
        if session.wants_read() {
            let mut tmp = [0u8; 4096];
            let mut buf = ReadBuf::new(&mut tmp);

            match Pin::new(io).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len();
                    if n > 0 {
                        made_progress = true;
                        match session.read_tls(&mut &buf.filled()[..]) {
                            Ok(_) => {
                                // Process the new data
                                match session.process_new_packets() {
                                    Ok(_) => {}
                                    Err(err) => {
                                        return Poll::Ready(Err(Error::new(
                                            ErrorKind::Other,
                                            format!("TLS error: {:?}", err),
                                        )));
                                    }
                                }
                            }
                            Err(err) => return Poll::Ready(Err(Error::new(ErrorKind::Other, err))),
                        }
                    } else if n == 0 {
                        // EOF
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "unexpected EOF during TLS handshake",
                        )));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    // If we got this far, we made progress and we're done for now
    Poll::Ready(Ok(()))
}

/// TLS connector for initiating TLS connections using rustls.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector { inner }
    }
}

impl From<ClientConfig> for TlsConnector {
    fn from(inner: ClientConfig) -> TlsConnector {
        TlsConnector {
            inner: Arc::new(inner),
        }
    }
}

impl TlsConnector {
    /// Connect to a remote server using TLS
    pub async fn connect<IO>(
        &self,
        server_name: ServerName,
        io: IO,
    ) -> Result<ClientTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with_session_id_generator(server_name, io, |_| [0; 32]).await
    }

    /// Connect with custom session ID generator
    pub async fn connect_with_session_id_generator<IO, F>(
        &self,
        server_name: ServerName,
        mut io: IO,
        session_id_generator: F,
    ) -> Result<ClientTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&[u8]) -> [u8; 32],
    {
        // Create client connection
        let mut conn = match ClientConnection::new_with_session_id_generator(
            self.inner.clone(),
            server_name,
            session_id_generator,
        ) {
            Ok(conn) => conn,
            Err(err) => return Err(Error::new(ErrorKind::Other, err)),
        };

        // Drive the handshake to completion
        let mut stream = ClientTlsStream::new(io, conn);
        complete_handshake(&mut stream).await?;

        Ok(stream)
    }
}

/// TLS acceptor for accepting TLS connections using rustls.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl From<ServerConfig> for TlsAcceptor {
    fn from(inner: ServerConfig) -> TlsAcceptor {
        TlsAcceptor {
            inner: Arc::new(inner),
        }
    }
}

impl TlsAcceptor {
    /// Accept a TLS connection from a client
    pub async fn accept<IO>(&self, io: IO) -> Result<ServerTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = match ServerConnection::new(self.inner.clone()) {
            Ok(conn) => conn,
            Err(err) => return Err(Error::new(ErrorKind::Other, err)),
        };

        let mut stream = ServerTlsStream::new(io, conn);
        complete_handshake(&mut stream).await?;

        Ok(stream)
    }
}

/// Helper function to complete TLS handshake
async fn complete_handshake<IO, S>(stream: &mut TlsStream<IO, S>) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    S: Session,
{
    let mut write_buf = [0u8; 4096];
    let mut read_buf = [0u8; 4096];

    // Loop until handshake is complete
    while stream.session.is_handshaking() {
        // Write handshake data if needed
        while stream.session.wants_write() {
            let n = stream.session.write_tls(&mut write_buf.as_mut())?;
            stream.io.write_all(&write_buf[..n]).await?;
        }

        // Read handshake response if needed
        if stream.session.wants_read() {
            let n = stream.io.read(&mut read_buf).await?;
            if n == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected EOF during TLS handshake",
                ));
            }

            stream.session.read_tls(&mut &read_buf[..n])?;
            stream.session.process_new_packets()?;
        }
    }

    Ok(())
}

