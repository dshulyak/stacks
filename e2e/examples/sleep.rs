use std::{
    env,
    ffi::OsString,
    str::FromStr,
    thread::{scope, sleep},
    time::Duration,
};

use tracing::span;

fn main() {
    // execute syscall in rust
    let args: Vec<OsString> = env::args_os().collect();
    let threads = if args.len() > 1 {
        os_string_to_usize(&args[1])
    } else {
        10
    };
    let loops = if args.len() > 2 {
        os_string_to_usize(&args[2])
    } else {
        1
    };
    let duration = if args.len() > 3 {
        os_string_to_usize(&args[3]) as u64
    } else {
        1000
    };
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

fn os_string_to_usize(os_string: &OsString) -> usize {
    usize::from_str(os_string.to_str().expect("not a valid unicode")).expect("not a number")
}
