#![feature(type_alias_impl_trait)]

use std::{collections::HashMap, path::PathBuf, process::exit};
use std::error::Error;
use std::sync::Arc;
use clap::{Parser, Subcommand, ValueEnum};
use rustls_fork_shadow_tls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, EnvFilter};

use shadow_tls::{
    sip003::parse_sip003_options, RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode,
    WildcardSNI,
};

use serde::Deserialize;
use tokio::net::TcpStream;
use shadow_tls::tokio_relay_v2::{HashedReadStream, TokioRelayV2};
use shadow_tls::tokio_rustls_fork_shadow_tls_also::TlsConnector;

#[derive(Parser, Debug, Deserialize)]
#[clap(
    author,
    version,
    about,
    long_about = "A proxy to expose real tls handshake to the firewall.\nGithub: github.com/ihciah/shadow-tls"
)]
pub struct Args {
    #[clap(subcommand)]
    #[serde(flatten)]
    cmd: Commands,
    #[clap(flatten)]
    #[serde(flatten)]
    opts: Opts,
}

macro_rules! default_function {
    ($name: ident, $type: ident, $val: expr) => {
        fn $name() -> $type {
            $val
        }
    };
}

// default_function!(default_true, bool, true);
default_function!(default_false, bool, false);
default_function!(default_8080, String, "[::1]:8080".to_string());
default_function!(default_443, String, "[::]:443".to_string());
default_function!(default_wildcard_sni, WildcardSNI, WildcardSNI::Off);

#[derive(Parser, Debug, Default, Clone, Deserialize)]
struct Opts {
    #[clap(short, long, help = "Set parallelism manually")]
    threads: Option<u8>,
    #[serde(default = "default_false")]
    #[clap(long, help = "Disable TCP_NODELAY")]
    disable_nodelay: bool,
    #[serde(default = "default_false")]
    #[clap(long, help = "Enable TCP_FASTOPEN")]
    fastopen: bool,
    #[serde(default = "default_false")]
    #[clap(long, help = "Use v3 protocol")]
    v3: bool,
    #[serde(default = "default_false")]
    #[clap(long, help = "Strict mode(only for v3 protocol)")]
    strict: bool,
}

#[derive(Subcommand, Debug, Deserialize)]
enum Commands {
    #[clap(about = "Run client side")]
    #[serde(rename = "client")]
    Client {
        #[clap(
            long = "listen",
            default_value = "[::1]:8080",
            help = "Shadow-tls client listen address(like \"[::1]:8080\")"
        )]
        #[serde(default = "default_8080")]
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
    #[clap(about = "Run server side")]
    #[serde(rename = "server")]
    Server {
        #[clap(
            long = "listen",
            default_value = "[::]:443",
            help = "Shadow-tls server listen address(like \"[::]:443\")"
        )]
        #[serde(default = "default_443")]
        listen: String,
        #[clap(
            long = "server",
            help = "Your data server address(like \"127.0.0.1:8080\")"
        )]
        server_addr: String,
        #[clap(
            long = "tls",
            help = "TLS handshake server address(like \"cloud.tencent.com:443\", \"cloudflare.com:1.1.1.1:443;captive.apple.com;cloud.tencent.com\")",
            value_parser = parse_server_addrs
        )]
        tls_addr: TlsAddrs,
        #[clap(long = "password", help = "Password")]
        password: String,
        #[clap(
            long = "wildcard-sni",
            default_value = "off",
            help = "Use sni:443 as handshake server without predefining mapping(useful for bypass billing system like airplane wifi without modifying server config)"
        )]
        #[serde(default = "default_wildcard_sni")]
        wildcard_sni: WildcardSNI,
    },
    #[serde(skip)]
    Config {
        #[serde(skip)]
        #[clap(short, long, value_name = "FILE", help = "Path to config file")]
        config: PathBuf,
    },
}

fn parse_client_names(addrs: &str) -> anyhow::Result<TlsNames> {
    TlsNames::try_from(addrs)
}

fn parse_server_addrs(arg: &str) -> anyhow::Result<TlsAddrs> {
    TlsAddrs::try_from(arg)
}

fn read_config_file(filename: String) -> Args {
    let file = std::fs::File::open(filename);
    match file {
        Err(e) => {
            tracing::error!("cannot open config file: {}", e);
            exit(-1);
        }
        Ok(f) => match serde_json::from_reader(f) {
            Err(e) => {
                tracing::error!("cannot read config file: {}", e);
                exit(-1);
            }
            Ok(res) => res,
        },
    }
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
            Commands::Server {
                listen,
                server_addr,
                mut tls_addr,
                password,
                wildcard_sni,
            } => {
                tls_addr.set_wildcard_sni(wildcard_sni);
                Self::Server {
                    listen_addr: listen,
                    target_addr: server_addr,
                    tls_addr,
                    password,
                    nodelay: !args.opts.disable_nodelay,
                    fastopen: args.opts.fastopen,
                    v3,
                }
            }
            Commands::Config { config: _ } => {
                unreachable!()
            }
        }
    }
}

// SIP003 [https://shadowsocks.org/en/wiki/Plugin.html](https://shadowsocks.org/en/wiki/Plugin.html)
pub(crate) fn get_sip003_arg() -> Option<Args> {
    macro_rules! env {
        ($key: expr) => {
            match std::env::var($key).ok() {
                None => return None,
                Some(val) if val.is_empty() => return None,
                Some(val) => val,
            }
        };
        ($key: expr, $fail_fn: expr) => {
            match std::env::var($key).ok() {
                None => return None,
                Some(val) if val.is_empty() => {
                    $fail_fn;
                    return None;
                }
                Some(val) => val,
            }
        };
        (optional $key: expr) => {
            match std::env::var($key).ok() {
                None => "".to_string(),
                Some(val) if val.is_empty() => "".to_string(),
                Some(val) => val,
            }
        };
    }
    let config_file = env!(optional "CONFIG_FILE");
    if !config_file.is_empty() {
        return Some(read_config_file(config_file));
    }
    let ss_remote_host = env!("SS_REMOTE_HOST");
    let ss_remote_port = env!("SS_REMOTE_PORT");
    let ss_local_host = env!("SS_LOCAL_HOST");
    let ss_local_port = env!("SS_LOCAL_PORT");
    #[allow(unreachable_code)]
    let ss_plugin_options = env!("SS_PLUGIN_OPTIONS", {
        tracing::error!("need SS_PLUGIN_OPTIONS when as SIP003 plugin");
        exit(-1);
    });

    let opts = parse_sip003_options(&ss_plugin_options).unwrap();
    let opts: HashMap<_, _> = opts.into_iter().collect();

    let threads = opts.get("threads").map(|s| s.parse::<u8>().unwrap());
    let v3 = opts.get("v3").is_some();
    let passwd = opts
        .get("passwd")
        .expect("need passwd param(like passwd=123456)");

    let args_opts = crate::Opts {
        threads,
        v3,
        ..Default::default()
    };
    let args = if opts.get("server").is_some() {
        let tls_addr = opts
            .get("tls")
            .expect("tls param must be specified(like tls=xxx.com:443)");
        let tls_addrs = parse_server_addrs(tls_addr)
            .expect("tls param parse failed(like tls=xxx.com:443 or tls=yyy.com:1.2.3.4:443;zzz.com:443;xxx.com)");
        let wildcard_sni =
            WildcardSNI::from_str(opts.get("tls").map(AsRef::as_ref).unwrap_or_default(), true)
                .expect("wildcard_sni format error");
        Args {
            cmd: crate::Commands::Server {
                listen: format!("{ss_remote_host}:{ss_remote_port}"),
                server_addr: format!("{ss_local_host}:{ss_local_port}"),
                tls_addr: tls_addrs,
                password: passwd.to_owned(),
                wildcard_sni,
            },
            opts: args_opts,
        }
    } else {
        let host = opts
            .get("host")
            .expect("need host param(like host=www.baidu.com)");
        let hosts = parse_client_names(host).expect("tls names parse failed");
        Args {
            cmd: crate::Commands::Client {
                listen: format!("{ss_local_host}:{ss_local_port}"),
                server_addr: format!("{ss_remote_host}:{ss_remote_port}"),
                tls_names: hosts,
                password: passwd.to_owned(),
                alpn: Default::default(),
            },
            opts: args_opts,
        }
    };
    Some(args)
}

fn main2() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("rustls=off".parse().unwrap()),
        )
        .init();
    let mut args = get_sip003_arg().unwrap_or_else(Args::parse);
    if let Commands::Config { config } = args.cmd {
        args = read_config_file(config.to_str().unwrap().to_string());
    }
    let parallelism = get_parallelism(&args);
    let running_args = RunningArgs::from(args);
    tracing::info!("Start {parallelism}-thread {running_args}");
    if let Err(e) = ctrlc::set_handler(|| std::process::exit(0)) {
        tracing::error!("Unable to register signal handler: {e}");
    }
    let runnable = running_args.build().expect("unable to build runnable");
    runnable.start(parallelism).into_iter().for_each(|t| {
        if let Err(e) = t.join().expect("couldn't join on the associated thread") {
            tracing::error!("Thread exit: {e}");
        }
    });
}

fn get_parallelism(args: &Args) -> usize {
    if let Some(n) = args.opts.threads {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}


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

