fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let exit = licoarc_client::cli::run(&arguments, &mut out, &mut err);
    std::process::exit(exit.0);
}
