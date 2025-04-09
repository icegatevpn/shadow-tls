#![feature(impl_trait_in_assoc_type)]

mod client;
mod helper_v2;
mod server;
pub mod sip003;
mod util;

// pub mod tokio_relay_v2;
pub mod tokio_rustls_fork_shadow_tls_also;

use std::{fmt::Display, thread::JoinHandle};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tracing::{debug, info};

pub use crate::{
    client::{ShadowTlsClient, TlsExtConfig, TlsNames},
    server::{ShadowTlsServer, TlsAddrs},
    // tokio_relay_v2::TokioShadowTlsV2Relay,
    util::{V3Mode, WildcardSNI},
};

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
    pub fn build(self) -> anyhow::Result<Runnable> {
        match self {
            RunningArgs::Client {
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                fastopen,
                v3,
            } => Ok(Runnable::Client(ShadowTlsClient::new(
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                fastopen,
                v3,
            )?)),
            RunningArgs::Server {
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                fastopen,
                v3,
            } => Ok(Runnable::Server(ShadowTlsServer::new(
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                fastopen,
                v3,
            ))),
        }
    }

    // #[inline]
    // pub fn build_tokio(self) -> anyhow::Result<TokioRunnable> {
    //     match self {
    //         RunningArgs::Client {
    //             listen_addr,
    //             target_addr,
    //             tls_names,
    //             password,
    //             nodelay,
    //             ..
    //         } => {
    //             // We need to extract the SNI hostname from tls_names for relay
    //             let hostname = tls_names.to_string();
    //             let hostname = hostname.trim_start_matches('[').trim_end_matches(']');
    //
    //             // Create the TokioShadowTlsV2Relay
    //             let relay = TokioShadowTlsV2Relay::new(
    //                 listen_addr,
    //                 hostname.to_string(),
    //                 target_addr,
    //                 password,
    //                 nodelay,
    //             );
    //
    //             Ok(TokioRunnable::Client(relay))
    //         },
    //         RunningArgs::Server { .. } => {
    //             Err(anyhow::anyhow!(
    //                     "Tokio implementation for server is not available yet"
    //                 ))
    //         },
    //     }
    // }
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
                write!(f, "Client with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server names: {tls_names}\nTLS Extension: {tls_ext}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}")
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
                write!(f, "Server with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server address: {tls_addr}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}")
            }
        }
    }
}

#[derive(Clone)]
pub enum Runnable {
    Client(ShadowTlsClient),
    Server(ShadowTlsServer),
}

// #[derive(Clone)]
// pub enum TokioRunnable {
//     Client(TokioShadowTlsV2Relay),
//     // Add Server variant when implemented
// }


// impl TokioRunnable {
//     /// Start the TokioRunnable with the specified number of worker threads.
//     /// Returns the Tokio Runtime that can be used to manage the application lifetime.
//     pub fn start(&self, parallelism: usize) -> anyhow::Result<Runtime> {
//         tracing::debug!("Starting TokioRunnable with {} threads", parallelism);
//
//         // Build a multi-threaded Tokio runtime
//         let runtime = RuntimeBuilder::new_multi_thread()
//             .worker_threads(parallelism)
//             .enable_all()
//             .build()
//             .map_err(|e| anyhow::anyhow!("Failed to build Tokio runtime: {}", e))?;
//
//         match self {
//             TokioRunnable::Client(relay) => {
//                 let relay_clone = relay.clone();
//
//                 // Spawn the relay service on the runtime
//                 runtime.spawn(async move {
//                     info!("Starting Shadow-TLS client relay service");
//                     if let Err(e) = relay_clone.serve().await {
//                         tracing::error!("Shadow-TLS relay service error: {}", e);
//                     }
//                 });
//             }
//         }
//
//         Ok(runtime)
//     }
// }

impl Runnable {
    async fn serve(self) -> anyhow::Result<()> {
        match self {
            Runnable::Client(c) => c.serve().await,
            Runnable::Server(s) => s.serve().await,
        }
    }

    pub fn start(&self, parallelism: usize) -> Vec<JoinHandle<anyhow::Result<()>>> {
        // 8 threads are enough for resolving domains
        const MAX_BLOCKING_THREADS: usize = 8;

        let mut threads = Vec::new();
        let shared_pool =
            monoio::blocking::DefaultThreadPool::new(MAX_BLOCKING_THREADS.min(2 * parallelism));
        for _ in 0..parallelism {
            let runnable_clone = self.clone();
            let shared_pool = Box::new(shared_pool.clone());
            let t = std::thread::spawn(move || {
                let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .attach_thread_pool(shared_pool)
                .enable_timer()
                .build()
                .expect("unable to build monoio runtime(please refer to: https://github.com/ihciah/shadow-tls/wiki/How-to-Run#common-issues)");
                rt.block_on(runnable_clone.serve())
            });
            threads.push(t);
        }
        threads
    }
}
