use std::io;
fn main() -> io::Result<()> {
    relayforge_mcp::stdio::serve(io::stdin().lock(), io::stdout().lock())
}
