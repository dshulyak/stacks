use std::{
    thread::{scope, sleep},
    time::Duration,
};

use clap::Parser;

struct Locker {
    lock: std::sync::Mutex<i32>,
}

impl Locker {
    fn new() -> Self {
        Self {
            lock: std::sync::Mutex::new(0),
        }
    }

    fn inc(&self, sleep_duration: Duration) {
        let mut guard = self.lock.lock().unwrap();
        sleep(sleep_duration);
        *guard += 1;
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "1000", help = "sleep duration in milliseconds")]
    duration: u64,
}

fn main() {
    let opt = Opt::parse();
    let sleep_duration = Duration::from_millis(opt.duration);

    let state = &Locker::new();
    scope(|s| {
        s.spawn(|| {
            state.inc(sleep_duration);
        });
        s.spawn(|| {
            state.inc(sleep_duration);
        });
    });
    sleep(sleep_duration);
}
