use crate::Commands::Client;
use clap::{Parser, Subcommand, ValueEnum};
use std::{path::PathBuf, process::exit, sync::Arc};
use tokio::signal;
use tokio_client::{RunningArgs, TlsExtConfig, TlsNames, V3Mode};
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt, prelude::*};

// Import your relay implementation
pub mod tokio_relay_v2;

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = "A proxy to expose real tls handshake to the firewall with Tokio."
)]
struct Args {
    #[clap(subcommand)]
    cmd: Commands,
    #[clap(flatten)]
    opts: Opts,
}

fn default_false() -> bool {
    false
}
fn default_8080() -> String {
    "[::1]:8080".to_string()
}
fn default_443() -> String {
    "[::]:443".to_string()
}

#[derive(Parser, Debug, Default, Clone)]
struct Opts {
    #[clap(short, long, help = "Set parallelism manually")]
    threads: Option<u8>,
    #[clap(long, help = "Disable TCP_NODELAY")]
    #[clap(default_value_t = false)]
    disable_nodelay: bool,
    #[clap(long, help = "Enable TCP_FASTOPEN")]
    #[clap(default_value_t = false)]
    fastopen: bool,
    #[clap(long, help = "Use v3 protocol")]
    #[clap(default_value_t = false)]
    v3: bool,
    #[clap(long, help = "Strict mode(only for v3 protocol)")]
    #[clap(default_value_t = false)]
    strict: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[clap(about = "Run client side with Tokio")]
    Client {
        #[clap(
            long = "listen",
            default_value = "[::1]:8080",
            help = "Shadow-tls client listen address(like \"[::1]:8080\")"
        )]
        listen: String,
        #[clap(
            long = "server",
            help = "Your shadow-tls server address(like \"1.2.3.4:443\")"
        )]
        server_addr: String,
        #[clap(
            long = "sni",
            help = "TLS handshake SNIs(like \"cloud.tencent.com\", \"captive.apple.com;cloud.tencent.com\")",
            value_parser = parse_client_names
        )]
        tls_names: TlsNames,
        #[clap(long = "password", help = "Password")]
        password: String,
        #[clap(
            long = "alpn",
            help = "Application-Layer Protocol Negotiation list(like \"http/1.1\", \"http/1.1;h2\")",
            value_delimiter = ';'
        )]
        alpn: Option<Vec<String>>,
    },
}

fn parse_client_names(addrs: &str) -> anyhow::Result<TlsNames> {
    TlsNames::try_from(addrs)
}

fn get_parallelism(args: &Args) -> usize {
    if let Some(n) = args.opts.threads {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

impl From<Args> for RunningArgs {
    fn from(args: Args) -> Self {
        let v3 = match (args.opts.v3, args.opts.strict) {
            (true, true) => V3Mode::Strict,
            (true, false) => V3Mode::Lossy,
            (false, _) => V3Mode::Disabled,
        };

        match args.cmd {
            Commands::Client {
                listen,
                server_addr,
                tls_names,
                password,
                alpn,
            } => Self::Client {
                listen_addr: listen,
                target_addr: server_addr,
                tls_names,
                tls_ext: TlsExtConfig::from(alpn),
                password,
                nodelay: !args.opts.disable_nodelay,
                fastopen: args.opts.fastopen,
                v3,
            },
        }
    }
}
fn test_client_args() -> Args {
    let args = Args {
        cmd: Client {
            listen: "127.0.0.1:666".to_string(),
            server_addr: "127.0.0.1:4432".to_string(),
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
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy()
                .add_directive("rustls=off".parse().unwrap()),
        )
        .init();

    let args = test_client_args();

    // Get thread count for parallelism
    let parallelism = get_parallelism(&args);

    // Convert args to RunningArgs and build TokioRunnable
    let running_args = RunningArgs::from(args);
    tracing::info!("Starting {parallelism}-thread {running_args}");

    // Build the Tokio runnable
    let tokio_runnable = running_args.build_tokio()?;
    let handle = tokio::runtime::Handle::current();
    tokio_runnable.run_on_runtime(&handle, parallelism)?;
    tracing::info!("Service started. Press Ctrl+C to stop");
    signal::ctrl_c().await?;
    tracing::info!("Received Ctrl+C, shutting down");

    Ok(())
}
