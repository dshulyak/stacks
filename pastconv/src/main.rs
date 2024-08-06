use std::{path::PathBuf, str};

use anyhow::{Context, Result};
use clap::Parser;
use common::session;

mod common;
mod pprof;
mod trace;

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
    Trace {
        #[clap(
            short,
            long,
            help = "path to the file where exported json will be stored",
            default_value = "/tmp/trace.json"
        )]
        destination: PathBuf,
        #[clap(index(1), num_args = 1.., help = "path to queries that should be added to the trace")]
        queries: Vec<PathBuf>,
    },
}

#[derive(Parser)]
enum PprofCommand {
    #[clap(aliases = &["c"], about = "samples of cpu profile")]
    Cpu {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    #[clap(aliases = &["o"], about = "waiting to be run. it can be IO, sychronization, time")]
    Offcpu {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    #[clap(aliases = &["r"], about = "rss profile. stacks are collected when page is requested in kernel")]
    Rss {
        #[clap(index = 1, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: String,
    },
    #[clap(
        about = r#"generate pprof from any custom query. sql query is expected to return rows with 3 columns.
first column is a collection with triples (name - utf8 string, address - u64, offset - u64).
second column is a number of collected samples - i64.
third column can be any data that is useful for pprof, for example in offcpu profile it can be a total waiting time - u64.    
"#
    )]
    Raw {
        #[clap(index = 1, help = "file with sql query")]
        query_file: PathBuf,
        #[clap(short, long, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: Option<String>,
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
            PprofCommand::Raw { query_file, command } => {
                let query = std::fs::read_to_string(query_file)?;
                pprof::pprof(&opt.register, &destination, &query, command.as_deref(), binary).await
            }
        },
        Command::Trace { destination, queries } => {
            let ctx = session(&opt.register).await?;
            let queries = queries
                .iter()
                .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
                .collect::<Result<Vec<_>>>()?;
            trace::export(&ctx, queries, destination).await
        }
    }
}
