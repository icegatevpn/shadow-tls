use std::error::Error;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use tokio_client::tokio_relay_v2::TokioShadowTlsV2Relay;

// Constants for the test
const SHADOW_TLS_SERVER_ADDR: &str = "127.0.0.1:4432";
const TEST_HTTP_SERVER_ADDR: &str = "127.0.0.1:8888";
const RELAY_ADDR: &str = "127.0.0.1:8080";
const PASSWORD: &str = "pwd1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Check which component to run
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage:");
        println!("  --http-server   Run test HTTP server");
        println!("  --relay         Run Shadow-TLS relay");
        println!("  --client-test   Run client test");
        println!("  --full-test     Run full test (starts all components)");
        return Ok(());
    }

    match args[1].as_str() {
        "--http-server" => {
            run_http_server().await?;
        }
        "--relay" => {
            run_relay().await?;
        }
        "--client-test" => {
            run_client_test().await?;
        }
        "--full-test" => {
            run_full_test().await?;
        }
        _ => {
            println!("Unknown option: {}", args[1]);
        }
    }

    Ok(())
}

async fn run_http_server() -> Result<(), Box<dyn Error>> {
    println!("Starting test HTTP server on {}", TEST_HTTP_SERVER_ADDR);

    let listener = TcpListener::bind(TEST_HTTP_SERVER_ADDR).await?;

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("HTTP server received connection from: {}", addr);

        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            let n = match socket.read(&mut buffer).await {
                Ok(n) if n == 0 => return, // connection closed
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Failed to read from socket: {}", e);
                    return;
                }
            };

            let request = String::from_utf8_lossy(&buffer[0..n]);
            println!("HTTP request:\n{}", request);

            // Generate a simple HTTP response
            let response = "HTTP/1.1 200 OK\r\n\
                            Content-Type: text/plain\r\n\
                            Content-Length: 28\r\n\
                            Connection: close\r\n\
                            \r\n\
                            Shadow-TLS test successful!\n";

            if let Err(e) = socket.write_all(response.as_bytes()).await {
                eprintln!("Failed to write to socket: {}", e);
                return;
            }
        });
    }
}

async fn run_relay() -> std::io::Result<()> {
    println!("Starting Shadow-TLS relay on {} -> {}", RELAY_ADDR, SHADOW_TLS_SERVER_ADDR);

    let relay = TokioShadowTlsV2Relay::new(
        RELAY_ADDR.to_string(),
        SHADOW_TLS_SERVER_ADDR.to_string(),
        TEST_HTTP_SERVER_ADDR.to_string(),
        PASSWORD.to_string(),
        true,
    );

    relay.serve().await
}

async fn run_client_test() -> Result<(), Box<dyn Error>> {
    println!("Running client test to relay at {}", RELAY_ADDR);

    // Give the relay and services time to start if needed
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut stream = match TcpStream::connect(RELAY_ADDR).await {
        Ok(stream) => {
            println!("Connected to relay successfully");
            stream
        },
        Err(e) => {
            println!("Failed to connect to relay: {}", e);
            return Err(e.into());
        }
    };

    // Send a simple HTTP request
    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await?;

    // Read the response
    let mut response = Vec::new();
    let bytes_read = stream.read_to_end(&mut response).await?;

    println!("Received {} bytes from server", bytes_read);
    println!("HTTP Response:\n{}", String::from_utf8_lossy(&response));

    if response.is_empty() {
        println!("Test failed: Empty response");
        return Err("Empty response".into());
    }

    if String::from_utf8_lossy(&response).contains("Shadow-TLS test successful!") {
        println!("✅ Test passed: Shadow-TLS relay is working correctly!");
    } else {
        println!("❌ Test failed: Unexpected response content");
    }

    Ok(())
}

async fn run_full_test() -> Result<(), Box<dyn Error>> {
    println!("Starting full test with all components");

    // Start HTTP server in a separate task
    tokio::spawn(async {
        if let Err(e) = run_http_server().await {
            eprintln!("HTTP server error: {}", e);
        }
    });

    // Give HTTP server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start shadow-tls server using the monoio-based command (assuming it's installed)
    let shadow_tls_server = tokio::process::Command::new("shadow-tls")
        .args([
            "server",
            "--listen", SHADOW_TLS_SERVER_ADDR,
            "--server", TEST_HTTP_SERVER_ADDR,
            "--tls", "captive.apple.com",
            "--password", PASSWORD,
        ])
        .spawn();

    match shadow_tls_server {
        Ok(mut child) => {
            println!("Started shadow-tls server process");

            // Start the relay in a separate task
            tokio::spawn(async {
                if let Err(e) = run_relay().await {
                    eprintln!("Relay error: {}", e);
                }
            });

            // Give relay time to start
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Run the client test
            let test_result = run_client_test().await;

            // Terminate the shadow-tls server process
            let _ = child.kill().await;

            test_result
        },
        Err(e) => {
            println!("Failed to start shadow-tls server: {}", e);
            println!("Do you have the shadow-tls binary installed?");
            println!("If not, you can start it manually and then run the relay and client tests separately.");
            Err(e.into())
        }
    }
}

// Helper function to check if shadow-tls server is already running
async fn is_port_in_use(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).await.is_ok()
}