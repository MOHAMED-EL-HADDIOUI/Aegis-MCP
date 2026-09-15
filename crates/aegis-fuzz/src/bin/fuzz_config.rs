//! `fuzz-config` binary: run the config/taint/classifier/signing target
//! over a corpus dir.
//!
//! Usage: `cargo run -p aegis-fuzz --bin fuzz-config [corpus_dir] [iters_per_seed]`
//! Defaults: `tests/fuzz/corpus`, 1000. Fixed PRNG seed => reproducible.
use aegis_fuzz::{load_seeds, run_target, target_config};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("tests/fuzz/corpus");
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let seeds = load_seeds(corpus);
    eprintln!(
        "fuzz-config: {} seeds x {} iters (corpus: {})",
        seeds.len(),
        iters,
        corpus
    );
    let stats = run_target(target_config, &seeds, iters, 0xC0F16, 4096);
    println!(
        "target=config inputs={} panics={} {}",
        stats.inputs,
        stats.panics,
        stats.first_panic.as_deref().unwrap_or("no panics")
    );
    if stats.panics > 0 {
        std::process::exit(1);
    }
}
