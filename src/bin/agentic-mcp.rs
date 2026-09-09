fn main() {
    if let Err(error) = agentic_jwt::mcp::cli(std::env::args().skip(1).collect()) {
        eprintln!("agentic-mcp: {error}");
        std::process::exit(1);
    }
}
