use std::hint::black_box;

use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(index(1), default_value_t = 1024, help = "memory size in MB")]
    size: usize,
}

fn main() {
    let opt = Opt::parse();
    let mut v = vec![0u8; opt.size << 20];
    for i in v.iter_mut() {
        // this line should trigger page faults and will be captured as offset
        *i = 11;
    }
    black_box(v);
}
