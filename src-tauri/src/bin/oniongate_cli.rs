#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = oniongate_lib::cli::run(&args).await;
    std::process::exit(code);
}
