use std::{path::PathBuf, str};

use anyhow::Result;
use clap::Parser;

pub mod common;
pub mod pprof;

const CPU_PPROF_SQL: &str = include_str!("sql/cpu_ustacks_for_command.sql");
const OFFCPU_PPROF_SQL: &str = include_str!("sql/offcpu_stacks_for_command.sql");
const RSS_PPROF_SQL: &str = include_str!("sql/ustack_rss_growth_for_command.sql");

#[derive(Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Command,
    #[clap(short, long, global = true, default_value = "/tmp/past/STACKS-*.parquet")]
    register: String,
    #[clap(short, long, global = true, help = "print version and exit")]
    version: bool,
}

#[derive(Parser)]
enum Command {
    Pprof {
        #[clap(short, long, global = true, default_value = "/tmp/pprof.pb")]
        destination: PathBuf,
        #[clap(short, long, global = true, help = "path to the binary file")]
        binary: Option<PathBuf>,
        #[clap(subcommand)]
        cmd: PprofCommand,
    },
}

#[derive(Parser)]
enum PprofCommand {
    #[clap(aliases = &["c"])]
    Cpu {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    #[clap(aliases = &["o"])]
    Offcpu {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    #[clap(aliases = &["r"])]
    Rss {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    Raw {
        #[clap(index = 1, help = "file with sql query")]
        query_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    if opt.version {
        println!("pastconv {}", env!("VERSION"));
        return Ok(());
    }
    match opt.cmd {
        Command::Pprof {
            destination,
            cmd,
            binary,
        } => match cmd {
            PprofCommand::Cpu { command } => {
                pprof::pprof(&opt.register, &destination, CPU_PPROF_SQL, Some(&command), binary).await
            }
            PprofCommand::Offcpu { command } => {
                pprof::pprof(&opt.register, &destination, OFFCPU_PPROF_SQL, Some(&command), binary).await
            }
            PprofCommand::Rss { command } => {
                pprof::pprof(&opt.register, &destination, RSS_PPROF_SQL, Some(&command), binary).await
            }
            PprofCommand::Raw { query_file } => {
                let query = std::fs::read_to_string(query_file)?;
                pprof::pprof(&opt.register, &destination, &query, None, binary).await
            }
        },
    }
}
