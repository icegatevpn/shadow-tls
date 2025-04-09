use crate::tokio_relay_v2::TokioShadowTlsV2Relay;
use rand::seq::IndexedRandom;
use rustls_fork_shadow_tls::ServerName;
use serde::Deserialize;
use std::convert::TryFrom;
use std::fmt::Display;
use tokio::runtime::{Builder as RuntimeBuilder, Handle, Runtime};
use tracing::{debug, info};
pub mod tokio_relay_v2;

#[derive(Clone, Debug, PartialEq)]
pub struct TlsNames(Vec<ServerName>);

impl TlsNames {
    #[inline]
    pub fn random_choose(&self) -> &ServerName {
        self.0.choose(&mut rand::rng()).unwrap()
    }
}
impl std::fmt::Display for TlsNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl TryFrom<&str> for TlsNames {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v: Result<Vec<_>, _> = value.trim().split(';').map(ServerName::try_from).collect();
        let v = v.map_err(Into::into).and_then(|v| {
            if v.is_empty() {
                Err(anyhow::anyhow!("empty tls names"))
            } else {
                Ok(v)
            }
        })?;
        Ok(Self(v))
    }
}

#[derive(Default, Debug)]
pub struct TlsExtConfig {
    alpn: Option<Vec<Vec<u8>>>,
}
impl Display for TlsExtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.alpn.as_ref() {
            Some(alpns) => {
                write!(f, "ALPN(Some(")?;
                for alpn in alpns.iter() {
                    write!(f, "{},", String::from_utf8_lossy(alpn))?;
                }
                write!(f, "))")?;
            }
            None => {
                write!(f, "ALPN(None)")?;
            }
        }
        Ok(())
    }
}
impl From<Option<Vec<String>>> for TlsExtConfig {
    fn from(maybe_alpns: Option<Vec<String>>) -> Self {
        Self {
            alpn: maybe_alpns.map(|alpns| alpns.into_iter().map(Into::into).collect()),
        }
    }
}
#[derive(Copy, Clone, Debug)]
pub enum V3Mode {
    Disabled,
    Lossy,
    Strict,
}
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TlsAddrs {
    dispatch: rustc_hash::FxHashMap<String, String>,
    fallback: String,
    wildcard_sni: WildcardSNI,
}

impl std::fmt::Display for V3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V3Mode::Disabled => write!(f, "disabled"),
            V3Mode::Lossy => write!(f, "enabled(lossy)"),
            V3Mode::Strict => write!(f, "enabled(strict)"),
        }
    }
}
impl std::fmt::Display for WildcardSNI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WildcardSNI::Off => write!(f, "off"),
            WildcardSNI::Authed => write!(f, "authed"),
            WildcardSNI::All => write!(f, "all"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, clap::ValueEnum, Deserialize)]
pub enum WildcardSNI {
    /// Disabled
    #[serde(rename = "off")]
    Off,
    /// For authenticated client only(may be differentiable); in v2 protocol it is eq to all.
    #[serde(rename = "authed")]
    Authed,
    /// For all request(may cause service abused but not differentiable)
    #[serde(rename = "all")]
    All,
}
impl Default for WildcardSNI {
    fn default() -> Self {
        Self::Off
    }
}
#[derive(Clone)]
pub enum TokioRunnable {
    Client(TokioShadowTlsV2Relay),
    // Add Server variant when implemented
}
impl TokioRunnable {
    /// Run the TokioRunnable on the provided runtime handle.
    ///
    /// This method is designed to be used with an existing Tokio runtime,
    /// such as the one created by #[tokio::main].
    pub fn run_on_runtime(&self, handle: &Handle, parallelism: usize) -> anyhow::Result<()> {
        tracing::debug!(
            "Running TokioRunnable on provided runtime with {} threads",
            parallelism
        );

        match self {
            TokioRunnable::Client(relay) => {
                let relay_clone = relay.clone();

                // Spawn the relay service on the runtime
                handle.spawn(async move {
                    info!("Starting Shadow-TLS client relay service");
                    if let Err(e) = relay_clone.serve().await {
                        tracing::error!("Shadow-TLS relay service error: {}", e);
                    }
                });
            }
        }

        Ok(())
    }
    /// Start the TokioRunnable with a new runtime.
    ///
    /// IMPORTANT: This method should NOT be called from within an existing Tokio runtime
    /// as it will create a new runtime. Use run_on_runtime() instead if you're already
    /// within a Tokio runtime (like inside #[tokio::main]).
    pub fn start_with_new_runtime(
        &self,
        parallelism: usize,
    ) -> anyhow::Result<tokio::runtime::Runtime> {
        debug!(
            "Starting TokioRunnable with new runtime with {} threads",
            parallelism
        );

        // Build a multi-threaded Tokio runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(parallelism)
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build Tokio runtime: {}", e))?;

        // Run the service on the new runtime
        self.run_on_runtime(&runtime.handle(), parallelism)?;

        Ok(runtime)
    }
}
pub enum RunningArgs {
    Client {
        listen_addr: String,
        target_addr: String,
        tls_names: TlsNames,
        tls_ext: TlsExtConfig,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
    },
    Server {
        listen_addr: String,
        target_addr: String,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
    },
}
impl RunningArgs {
    #[inline]
    pub fn build_tokio(self) -> anyhow::Result<TokioRunnable> {
        match self {
            RunningArgs::Client {
                listen_addr,
                target_addr,
                tls_names,
                password,
                nodelay,
                ..
            } => {
                // We need to extract the SNI hostname from tls_names for relay
                let hostname = tls_names.to_string();
                let hostname = hostname.trim_start_matches('[').trim_end_matches(']');

                // Create the TokioShadowTlsV2Relay
                let relay = TokioShadowTlsV2Relay::new(
                    listen_addr,
                    hostname.to_string(),
                    target_addr,
                    password,
                    nodelay,
                );

                Ok(TokioRunnable::Client(relay))
            }
            RunningArgs::Server { .. } => Err(anyhow::anyhow!(
                "Tokio implementation for server is not available yet"
            )),
        }
    }
}

impl std::fmt::Display for TlsAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(wildcard-sni:{})", self.wildcard_sni)?;
        for (k, v) in self.dispatch.iter() {
            write!(f, "{k}->{v};")?;
        }
        write!(f, "fallback->{}", self.fallback)
    }
}
impl Display for RunningArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client {
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                nodelay,
                fastopen,
                v3,
                ..
            } => {
                write!(
                    f,
                    "Client with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server names: {tls_names}\nTLS Extension: {tls_ext}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}"
                )
            }
            Self::Server {
                listen_addr,
                target_addr,
                tls_addr,
                nodelay,
                fastopen,
                v3,
                ..
            } => {
                write!(
                    f,
                    "Server with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server address: {tls_addr}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}"
                )
            }
        }
    }
}
