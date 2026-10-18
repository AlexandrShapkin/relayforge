use std::io;
fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--http") {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(relayforge_mcp::http::run_from_env())
    } else {
        relayforge_mcp::stdio::serve(io::stdin().lock(), io::stdout().lock())
    }
}
