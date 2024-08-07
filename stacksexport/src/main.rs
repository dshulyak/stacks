use std::{path::PathBuf, str};

use anyhow::{Context, Result};
use clap::Parser;
use common::session;
use tracing::{info, level_filters::LevelFilter};

mod common;
mod pprof;
mod trace;

#[derive(Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Command,
    #[clap(short, long, global = true, default_value = "/tmp/stacks/STACKS-*.parquet")]
    register: String,
    #[clap(short, long, global = true, help = "print version and exit")]
    version: bool,
}

#[derive(Parser)]
enum Command {
    #[clap(
        about = r#"generate pprof from any custom query. sql query is expected to return rows with 3 columns.
    first column is a collection with triples (name - utf8 string, address - u64, offset - u64).
    second column is a number of collected samples - i64.
    third column can be any data that is useful for pprof, for example in offcpu profile it can be a total waiting time - u64.    
    "#
    )]
    Pprof {
        #[clap(short, long, global = true, default_value = "/tmp/pprof.pb")]
        destination: PathBuf,
        #[clap(short, long, global = true, help = "path to the binary file")]
        binary: Option<PathBuf>,
        #[clap(index = 1, help = "file with sql query")]
        query_file: PathBuf,
        #[clap(short, long, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: Option<String>,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let opt = Opt::parse();
    if opt.version {
        info!("stacksexport {}", env!("VERSION"));
        return Ok(());
    }
    match opt.cmd {
        Command::Pprof {
            destination,
            command,
            query_file,
            binary,
        } => {
            let query = std::fs::read_to_string(query_file)?;
            pprof::pprof(&opt.register, &destination, &query, command.as_deref(), binary).await?;
            info!("pprof is exported to {}", destination.display());    
            Ok(())
        }
        Command::Trace { destination, queries } => {
            let ctx = session(&opt.register).await?;
            let queries = queries
                .iter()
                .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
                .collect::<Result<Vec<_>>>()?;
            trace::export(&ctx, queries, &destination).await?;
            info!("trace is exported to {}", destination.display());
            Ok(())
        }
    }
}
