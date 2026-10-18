use std::io;
fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--http") {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(relayforge_mcp::http::run_from_env())
    } else if std::env::args().nth(1).as_deref() == Some("--readonly-stdio") {
        relayforge_mcp::stdio::serve_tunnel(io::stdin().lock(), io::stdout().lock())
    } else {
        relayforge_mcp::stdio::serve(io::stdin().lock(), io::stdout().lock())
    }
}
