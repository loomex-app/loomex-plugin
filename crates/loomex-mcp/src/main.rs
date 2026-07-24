use loomex_mcp::{ipc::ControlClient, serve, Server};

#[tokio::main]
async fn main() {
    // stdout is reserved for MCP JSON-RPC frames. Diagnostics always use stderr.
    if let Err(error) = serve(Server::new(ControlClient::from_environment())).await {
        eprintln!("loomex-mcp: {error}");
        std::process::exit(1);
    }
}
