use std::{env, fs, path::PathBuf, str};

use anyhow::{Context, Result};
use clap::Parser;
use common::session;
use tracing::{info, level_filters::LevelFilter};

mod common;
mod pprof;
mod trace;

fn default_register_path() -> PathBuf {
    let dir_wo_index = env::temp_dir().join("stacks");
    let mut next = 0;
    if let Ok(entries) = fs::read_dir(&dir_wo_index) {
        for entry in entries {
            let entry = entry.expect("unable to read entry");
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    if let Some(name) = name.to_str() {
                        if let Ok(index) = name.parse::<u32>() {
                            next = next.max(index);
                        }
                    }
                }
            }
        }
    }
    dir_wo_index.join(next.to_string())
}

#[derive(Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Command,
    #[clap(short, long, global = true, default_value = default_register_path().into_os_string())]
    register: String,
    #[clap(short, long, global = true, help = "print version and exit")]
    version: bool,
    #[clap(short,
        long,
        global = true,
        default_value_t = default_data_directory(),
        help = r#"directory to store exported data. 
        the default directory is not hidden as firefox/chrome fails to open html files from hidden directories"#
    )]
    directory: String,
    #[clap(
        short,
        long,
        global = true,
        help = "do not open the output file in the default viewer"
    )]
    no_open: bool,
}

#[derive(Parser)]
enum Command {
    #[clap(
        about = r#"generate pprof from any custom query. sql query is expected to return rows with 3 columns.
    first column is a collection with triples (name - utf8 string, address - u64, offset - u64).
    second column is a number of collected samples - i64.
    third column can be any data that is useful for pprof, for example in offcpu profile it can be a total waiting time - u64.
    EXAMPLES:
        stacksexport pprof ./stacksexport/sql/pprof/rss_ustacks_growth_for_buildid.sql -b ./target/release/stacks
    "#
    )]
    Pprof {
        #[clap(short, long, help = "path to the binary file")]
        binary: Option<PathBuf>,
        #[clap(
            short,
            long,
            help = "include inlined functions in the profile. inlined option works only if binary is provided",
            requires = "binary"
        )]
        inlined: bool,
        #[clap(index = 1, help = "file with sql query")]
        query_file: PathBuf,
        #[clap(short, long, help = "name of the process, as it is recorded in /proce/<pid>/comm")]
        command: Option<String>,
        #[clap(
            short,
            long,
            help = "include offset after the symbol name. it can be useful to avoid cycles in pprof"
        )]
        offset: bool,
    },
    #[clap(about = r#"generate traces from a list of queries. 
    EXAMPLES:
        PATH=$PATH:~/catapult/tracing/bin stacksexport trace ./stacksexport/sql/traceview/switch_with_stacks.sql
    "#)]
    Trace {
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
            command,
            query_file,
            binary,
            offset,
            inlined,
        } => {
            ensure_dir(&PathBuf::from(&opt.directory))?;
            let destination = next_file(&PathBuf::from(&opt.directory), "pprof", "pprof")?;
            let query = std::fs::read_to_string(query_file)?;
            pprof::pprof(
                &opt.register,
                &destination,
                &query,
                command.as_deref(),
                binary,
                offset,
                inlined,
            )
            .await?;
            info!("pprof is exported to {}", destination.display());
            if !opt.no_open {
                open_pprof(&destination).with_context(|| format!("pprof {}", destination.display()))?;
            }
            Ok(())
        }
        Command::Trace { queries } => {
            ensure_dir(&PathBuf::from(&opt.directory))?;
            let destination = next_file(&PathBuf::from(&opt.directory), "traceview", "json")?;
            let ctx = session(&opt.register).await?;
            let queries = queries
                .iter()
                .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
                .collect::<Result<Vec<_>>>()?;
            trace::export(&ctx, queries, &destination).await?;
            info!("trace is exported to {}", destination.display());
            if !opt.no_open {
                open_traceviewer(&destination).with_context(|| format!("trace2html {}", destination.display()))?;
            }
            Ok(())
        }
    }
}

fn open_pprof(file: &PathBuf) -> Result<()> {
    std::process::Command::new("pprof")
        .arg("-http=:8080")
        .arg(file)
        .spawn()?
        .wait()?;
    Ok(())
}

fn open_traceviewer(file: &PathBuf) -> Result<()> {
    std::process::Command::new("trace2html").arg(file).spawn()?.wait()?;
    let html = file.with_extension("html");
    info!("traceview is exported to {}", html.display());
    std::process::Command::new("open").arg(html).spawn()?.wait()?;
    Ok(())
}

fn ensure_dir(dir: &PathBuf) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn default_data_directory() -> String {
    let dir = dirs::home_dir()
        .expect("home directory is not found")
        .join("stacks_export_data");
    dir.into_os_string().into_string().unwrap()
}

fn next_file(dir: &PathBuf, kind: &str, extension: &str) -> Result<PathBuf> {
    let index = next_index(dir, kind, extension)?.map_or(0, |i| i + 1);
    Ok(dir.join(format!("{}-{}.{}", kind, index, extension)))
}

fn next_index(dir: &PathBuf, kind: &str, extension: &str) -> Result<Option<usize>> {
    let mut max: Option<usize> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();
            if !name.contains(kind) || !name.contains(extension) {
                continue;
            }
            let name = name
                .strip_prefix(format!("{}-", kind).as_str())
                .ok_or_else(|| anyhow::anyhow!("can't strip {}- from {:?}", kind, path))?;
            let name = name
                .strip_suffix(format!(".{}", extension).as_str())
                .ok_or_else(|| anyhow::anyhow!("can't strip extension .{} from {:?}", extension, path))?;
            let index = name
                .parse::<usize>()
                .with_context(|| format!("parsing index from {}", name))?;
            max = Some(max.map_or(index, |m| m.max(index)));
        }
    }
    Ok(max)
}
