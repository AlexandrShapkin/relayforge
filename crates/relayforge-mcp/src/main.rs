use std::io;
fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--approve-change") {
        let id = std::env::args()
            .nth(2)
            .ok_or_else(|| io::Error::other("approval ID required"))?;
        if std::env::args().nth(3).is_some() {
            return Err(io::Error::other("unexpected arguments"));
        }
        relayforge_mcp::changes::approve_local(&id)
    } else if std::env::args().nth(1).as_deref() == Some("--http") {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(relayforge_mcp::http::run_from_env())
    } else if std::env::args().nth(1).as_deref() == Some("--sandbox-job-worker") {
        let id = std::env::args()
            .nth(2)
            .ok_or_else(|| io::Error::other("sandbox job ID required"))?;
        if std::env::args().nth(3).is_some() {
            return Err(io::Error::other("unexpected arguments"));
        }
        std::process::exit(relayforge_mcp::workstation_jobs::run_worker(&id));
    } else if std::env::args().nth(1).as_deref() == Some("--retire-ssh-worker") {
        let kind = std::env::args().nth(2)
            .ok_or_else(|| io::Error::other("retirement kind required"))?;
        if std::env::args().nth(3).is_some() {
            return Err(io::Error::other("unexpected arguments"));
        }
        std::process::exit(relayforge_mcp::workstation_retire::run_worker(&kind));
    } else if std::env::args().nth(1).as_deref() == Some("--readonly-worker") {
        relayforge_mcp::stdio::serve_tunnel_worker(io::stdin().lock(), io::stdout().lock())
    } else if std::env::args().nth(1).as_deref() == Some("--readonly-stdio") {
        relayforge_mcp::stdio::serve_tunnel(io::stdin().lock(), io::stdout().lock())
    } else {
        relayforge_mcp::stdio::serve(io::stdin().lock(), io::stdout().lock())
    }
}
