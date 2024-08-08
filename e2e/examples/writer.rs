use std::{io::Write, path::PathBuf};

use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(index(1))]
    path: PathBuf,
    #[clap(short, long, default_value_t = 1, help = "chunk size in MB")]
    chunk: u64,
    #[clap(short, long, default_value_t = 1 << 10, help="size in MB")]
    size: u64,
    #[clap(short, long)]
    fsync: bool,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let mut f = std::fs::File::create(opt.path)?;
    let buf = vec![0u8; (opt.chunk << 20) as usize];
    for _ in 0..(opt.size / opt.chunk) {
        f.write_all(&buf)?;
        if opt.fsync {
            f.sync_all()?;
        }
    }
    Ok(())
}
