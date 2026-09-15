//! `fuzz-protocol` binary: run the protocol target over a corpus dir.
//!
//! Usage: `cargo run -p aegis-fuzz --bin fuzz-protocol [corpus_dir] [iters_per_seed]`
//! Defaults: `tests/fuzz/corpus`, 1000. Fixed PRNG seed => reproducible.
use aegis_fuzz::{load_seeds, run_target, target_protocol};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("tests/fuzz/corpus");
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let seeds = load_seeds(corpus);
    eprintln!(
        "fuzz-protocol: {} seeds x {} iters (corpus: {})",
        seeds.len(),
        iters,
        corpus
    );
    let stats = run_target(target_protocol, &seeds, iters, 0xAE615, 4096);
    println!(
        "target=protocol inputs={} panics={} {}",
        stats.inputs,
        stats.panics,
        stats.first_panic.as_deref().unwrap_or("no panics")
    );
    if stats.panics > 0 {
        std::process::exit(1);
    }
}
