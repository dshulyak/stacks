use std::{
    thread::{scope, sleep},
    time::Duration,
};

use clap::Parser;
use tracing::span;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "10")]
    threads: usize,
    #[clap(short, long, default_value = "1")]
    loops: usize,
    #[clap(short, long, default_value = "1000")]
    duration: u64,
}

fn main() {
    let opt = Opt::parse();
    let threads = opt.threads;
    let loops = opt.loops;
    let duration = opt.duration;

    scope(|s| {
        let span = span!(tracing::Level::INFO, "sleep");
        for _ in 0..threads {
            let span = span.clone();
            s.spawn(move || {
                for _ in 0..loops {
                    let _enter = span.enter();
                    sleep(Duration::from_millis(duration));
                }
            });
        }
    });
}
