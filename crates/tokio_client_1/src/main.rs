use clap::{Parser, Subcommand, ValueEnum};
use std::{path::PathBuf, process::exit, sync::Arc};
use tokio::signal;
use tokio_client::{get_parallelism, Args, Commands, RunningArgs, TlsExtConfig, TlsNames, V3Mode};
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt, prelude::*};
use tokio_client::Commands::Client;

// Import your relay implementation
pub mod tokio_relay_v2;




fn default_false() -> bool {
    false
}
fn default_8080() -> String {
    "[::1]:8080".to_string()
}
fn default_443() -> String {
    "[::]:443".to_string()
}



fn test_client_args() -> Args {
    let args = Args {
        cmd: Client {
            listen: "127.0.0.1:666".to_string(),
            server_addr: "127.0.0.1:4433".to_string(),
            tls_names: TlsNames::try_from("captive.apple.com").unwrap(),
            password: "pwd1".to_string(),
            alpn: None,
        },
        opts: Default::default(),
    };
    args
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::TRACE.into())
                .from_env_lossy()
                .add_directive("rustls=off".parse().unwrap()),
        )
        .init();

    let args = test_client_args();

    // Convert args to RunningArgs and build TokioRunnable
    let running_args = RunningArgs::from(args);
    tracing::info!("Starting thread {running_args}");

    // Build the Tokio runnable
    let tokio_runnable = running_args.build_tokio()?;
    let handle = tokio::runtime::Handle::current();
    tokio_runnable.run_on_runtime(&handle)?;
    tracing::info!("Service started. Press Ctrl+C to stop");
    signal::ctrl_c().await?;
    tracing::info!("Received Ctrl+C, shutting down");

    Ok(())
}
