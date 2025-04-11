use crate::Commands::Client;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, TokioRunnable, V3Mode, WildcardSNI};
use std::path::PathBuf;
use std::process::exit;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

// If I can build and run this, then I'm good!
/*
Start shadow-tls server with: SERVER:
./shadow-tls server --listen 127.0.0.1:4432 --server 127.0.0.1:8888 --tls captive.apple.com --password pwd1

TEST:
curl --proxy 127.0.0.1:666 www.google.com
 */

fn parse_client_names(addrs: &str) -> anyhow::Result<TlsNames> {
    TlsNames::try_from(addrs)
}
fn parse_server_addrs(arg: &str) -> anyhow::Result<TlsAddrs> {
    TlsAddrs::try_from(arg)
}
macro_rules! default_function {
    ($name: ident, $type: ident, $val: expr) => {
        fn $name() -> $type {
            $val
        }
    };
}
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
// fn get_parallelism(args: &Args) -> usize {
//     if let Some(n) = args.opts.threads {
//         return n as usize;
//     }
//     std::thread::available_parallelism()
//         .map(|n| n.get())
//         .unwrap_or(1)
// }
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

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("rustls=off".parse().unwrap()),
        )
        .init();
    let mut args = test_client_args();

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
    let tokio_runnable = TokioRunnable::from(runnable);
    tokio_runnable.start(parallelism);
    // tokio_runnable.start(parallelism).into_iter().for_each(|t| {
    //     if let Err(e) = t.join().expect("couldn't join on the associated thread") {
    //         tracing::error!("Thread exit: {e}");
    //     }
    // });
}
