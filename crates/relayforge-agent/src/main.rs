use std::io;
fn main() -> io::Result<()> {
    relayforge_agent::stdio::serve(io::stdin().lock(), io::stdout().lock())
}
