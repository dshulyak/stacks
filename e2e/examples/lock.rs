use std::{
    thread::{scope, sleep},
    time::Duration,
};

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

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    let sleep_duration = if args.len() > 1 {
        Duration::from_millis(args[1].parse().unwrap())
    } else {
        Duration::from_secs(1)
    };

    let state = &Locker::new();
    scope(|s| {
        s.spawn(|| {
            state.inc(sleep_duration);
        });
        s.spawn(|| {
            state.inc(sleep_duration);
        });
    });
}
