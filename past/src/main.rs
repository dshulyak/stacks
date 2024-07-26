use std::{
    collections::HashSet, fs, io::Read, path::{Path, PathBuf}, sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    }, time::Duration
};

use anyhow::{Context, Result};
use bpf::{link, Program, Programs};
use clap::Parser;
use libbpf_rs::{MapFlags, RingBufferBuilder};
use tracing::{error, info, info_span, level_filters::LevelFilter, warn};
use tracing_subscriber::{prelude::*, Registry};

use crate::{
    parquet::Compression,
    state::Received,
    symbolizer::{BlazesymSymbolizer, Frames, Symbolizer},
};

mod past {
    include!(concat!(env!("OUT_DIR"), "/past.skel.rs"));
}
use past::*;

mod bpf;
mod bpf_profile;
mod parquet;
mod perf_event;
mod state;
mod symbolizer;
#[cfg(test)]
mod tests;

const DEFAULT_PROGRAMS: &str = "profile:u:99,rss:u:29,switch:k";

#[derive(Debug, Parser)]
struct Opt {
    #[clap(
        num_args = 1..,
        help = "filter all threads of the process by the process command name. value in /proc/<pid>/comm"
    )]
    commands: Vec<String>,

    #[clap(short, long, default_value = "/tmp/past/")]
    dir: PathBuf,

    #[clap(long, default_value = "STACKS")]
    prefix: String,

    #[clap(long, default_value = "zstd(1)")]
    compression: Compression,

    #[clap(
        short,
        long,
        default_value = "100000",
        help = "larger value will use more memory, but will improve compression"
    )]
    rows: usize,

    #[clap(
        short,
        long,
        default_value = "10",
        help = "file is a unit of paralellism in datafusion,
                if data is partitioned into several files datafusion will be able to process different files on different cores,
                additionally if file is not properly closed data will be lost."
    )]
    groups_per_file: usize,

    #[clap(
        short,
        num_args = 1..,
        value_delimiter = ',',
        default_value = DEFAULT_PROGRAMS,
        help = r#"list of bpf programs that will be collecting data.
examples:
- profile:u:99
    collect user stacks at 99hz frequency.
- rss:u:29
    collect user stacks on every rss change event.
- switch:ku:1us
    collect kernel and user stacks on context switch event.
    bpf collector will drop all spans that are shorter than 1us.
- switch:n
    do not collect stacks on context switch event.
"#,
    )]
    programs: Vec<String>,

    #[clap(
        long,
        default_value = "33554432",
        help = "define size in bytes of the ring buffer for events."
    )]
    bpf_events: u32,

    #[clap(
        long,
        default_value = "131072",
        help = "define size of the bpf stack map. each item in the map is atmost 1016 bytes (127 items of 8 bytes each)"
    )]
    bpf_stacks: u32,

    #[clap(long, default_value = "1s", help = "polling interval for bpf ringbuf")]
    poll: humantime::Duration,

    #[clap(
        short,
        long,
        help = "path to the binary instrumented with past_tracing usdt provider"
    )]
    usdt: Vec<PathBuf>,

    #[clap(
        long,
        default_value = "false",
        help = "enable debug output for bpf program. it will be in /sys/kernel/debug/tracing/trace_pipe"
    )]
    debug_bpf: bool,

    #[clap(long, default_value = "false", help = "print version and exit")]
    version: bool,
}

fn main() -> Result<()> {
    let registry = Registry::default()
        .with(
            tracing_past::PastSubscriber {}.with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        );
    tracing::dispatcher::set_global_default(registry.into()).expect("failed to set global default subscriber");

    let opt: Opt = Opt::parse();
    if opt.version {
        println!("past {}", env!("VERSION"));
        return Ok(());
    }
    if opt.commands.is_empty() {
        anyhow::bail!("at least one command must be provided");
    }
    // NOTE collections in clap derive are being designed
    // i didn't manage to make them work with a little bit of code
    let mut programs: Vec<Program> = vec![];
    for program in opt.programs.iter() {
        programs.push(program.as_str().try_into()?);
    }
    let programs = Programs::try_from_programs(programs.into_iter())?;
    info!(
        "running bpf programs: {} for commands {}",
        programs,
        opt.commands.join(", ")
    );

    let interrupt = Arc::new(AtomicBool::new(true));
    let interrupt_handler = interrupt.clone();
    ctrlc::set_handler(move || {
        interrupt_handler.store(false, Ordering::Relaxed);
    })?;

    ensure_exists(&opt.dir)?;

    let uptime = parse_uptime()?;
    let current_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("current unix time")?;
    let adjustment = (current_unix - uptime).as_nanos() as u64;

    let (mut skel, _links) = link(
        &programs,
        opt.usdt.iter(),
        opt.debug_bpf,
        opt.bpf_events,
        opt.bpf_stacks,
    )?;

    let zero: u8 = 0;
    for comm in opt.commands.iter() {
        let comm = null_terminated_array16_from_str(comm.as_str());
        skel.maps_mut()
            .filter_comm()
            .update(&comm, &zero.to_ne_bytes(), MapFlags::ANY)?;
    }
    let comms = opt.commands.iter().map(|c| c.as_str()).collect::<HashSet<_>>();
    // scan /proc after bpf prograns are attached
    // to be sure that target comm is discovered either from proc or if it was exec'ed
    let procs = scan_proc(&comms)?;
    for proc in procs.iter() {
        let mut maps = skel.maps_mut();
        maps.filter_tgid()
            .update(&proc.tgid.to_ne_bytes(), &zero.to_ne_bytes(), MapFlags::ANY)?;
    }
    let maps = skel.maps();
    let mut program = state::State::new(
        state::Config {
            directory: opt.dir,
            timestamp_adjustment: adjustment,
            groups_per_file: opt.groups_per_file,
            rows_per_group: opt.rows,
            perf_event_frequency: 1_000_000_000 / programs.profile_frequency() as i64,
            compression: opt.compression,
            _non_exhaustive: (),
        },
        MapFrames(maps.stackmap()),
        BlazesymSymbolizer::new(),
    )?;
    for proc in procs.iter() {
        let fake_exec_event = past_types::process_exec_event {
            timestamp: uptime.as_nanos() as u64,
            tgid: proc.tgid as u32,
            comm: proc.comm,
            ..Default::default()
        };
        program.on_event(Received::ProcessExec(&fake_exec_event))?;
    }

    let mut dropped_counter = 0;
    let sleep_interval = opt.poll.into();
    let progs = skel.progs();
    loop {
        match consume_events(&mut program, &maps, &progs, &mut dropped_counter, &interrupt, sleep_interval) {
            Ok(_) => break,
            Err(ErrorConsume::DroppedEvents(dropped)) => {
                warn!("program missed events {}. will need to reinitialize state", dropped);
                let span = info_span!("reinitialize");
                let _guard = span.enter();
                program.drop_known_state()?;
                let scanned = scan_proc(&comms)?;
                for comm in scanned {
                    let fake_exec_event = past_types::process_exec_event {
                        timestamp: uptime.as_nanos() as u64,
                        tgid: comm.tgid as u32,
                        comm: comm.comm,
                        ..Default::default()
                    };
                    program.on_event(Received::ProcessExec(&fake_exec_event))?;
                }
            }
            Err(err) => {
                error!("consume events: {:?}", err);
                break;
            }
        }
    }
    info!("trace interrupted, flushing pending data to file and exiting");
    program.exit_current_file()
}

#[derive(thiserror::Error, Debug)]
enum ErrorConsume {
    #[error("ringbuf capacity can't handle events rate. dropped events since previous {0}")]
    DroppedEvents(u64),
    #[error(transparent)]
    LibbpfError(#[from] libbpf_rs::Error),
}

fn consume_events<Fr: Frames, Sym: Symbolizer>(
    program: &mut state::State<Fr, Sym>,
    maps: &PastMaps,
    progs: &PastProgs,
    dropped_counter: &mut u64,
    interrupt: &Arc<AtomicBool>,
    poll_interval: Duration,
) -> Result<(), ErrorConsume> {
    let stats_fd = bpf_profile::enable()?;
    let mut builder = RingBufferBuilder::new();
    builder.add(maps.events(), |buf: &[u8]| {
        if let Err(err) = program.on_event(buf.into()) {
            error!("failed to process event: {:?}", err);
            1
        } else {
            0
        }
    })?;
    let mgr = builder.build().unwrap();
    let consume = info_span!("consume");

    loop {
        consume.in_scope(|| {
            if let Err(err) = mgr.poll(poll_interval) {
                if err.kind() == libbpf_rs::ErrorKind::Interrupted {
                    info!(
                        "process was interrupted {:?}. will try to consume remaining events",
                        err
                    );
                    _ = mgr.consume();
                } else {
                    warn!("consume from ring buffer: {:?}", err);
                }
            }
        });
        if !interrupt.load(Ordering::Relaxed) {
            return Ok(());
        }
        let updated_dropped_counter = count_dropped_events(maps.errors_counter())?;
        if updated_dropped_counter > *dropped_counter {
            let delta = updated_dropped_counter - *dropped_counter;
            *dropped_counter = updated_dropped_counter;
            return Err(ErrorConsume::DroppedEvents(delta));
        }
            let stats = stats_fd.get_stats(progs.handle__mm_trace_rss_stat())?;
            info!(
                "program {} runtime_ns: {} runtime_cnt: {}",
                stats.name,
                stats.runtime_ns,
                stats.runtime_cnt
            );
        
    }
}

struct MapFrames<'a>(&'a libbpf_rs::Map);

impl Frames for MapFrames<'_> {
    fn frames(&self, id: i32) -> Result<Vec<u64>> {
        let id = id.to_ne_bytes();
        let rst: Option<Vec<u8>> = self.0.lookup(&id, MapFlags::empty())?;
        let rst = rst.map(|frames| {
            let frames: &[u64] = bytemuck::cast_slice(&frames);
            let last_non_zero = frames.iter().rposition(|x| *x != 0).unwrap_or(0);
            frames[..=last_non_zero].to_vec()
        });
        match rst {
            Some(frames) => Ok(frames),
            None => Ok(vec![]),
        }
    }
}

// this value must match enum in past/src/bpf/past.h
// i need to lookup how to generate bindings for enums
const DROPPED_EVENTS: u32 = 0;

fn count_dropped_events(errors_counter: &libbpf_rs::Map) -> Result<u64, libbpf_rs::Error> {
    let key = DROPPED_EVENTS.to_ne_bytes();
    let rst = errors_counter.lookup_percpu(&key, MapFlags::empty())?;
    if let Some(rst) = rst {
        Ok(rst
            .iter()
            .map(|cpu| u64::from_ne_bytes(cpu.as_slice().try_into().expect("events counter must be 8 bytes long")))
            .sum())
    } else {
        Ok(0)
    }
}

fn ensure_exists(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn parse_uptime() -> anyhow::Result<Duration> {
    let mut uptime = String::new();
    fs::File::open("/proc/uptime")?.read_to_string(&mut uptime)?;
    // example format
    // 4039.25                  94816.49
    // seconds.fraction_seconds idle_seconds.fraction_seconds
    // i am only interested in the first part
    let mut parts = uptime.split_whitespace().flat_map(|x| x.split('.'));
    let seconds = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing seconds"))?
        .parse::<u64>()?;
    let fraction_seconds = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing fraction seconds"))?
        .parse::<u64>()?;
    Ok(Duration::from_secs(seconds) + Duration::from_millis(fraction_seconds * 10))
}

#[derive(Debug)]
struct Proc {
    tgid: i32,
    comm: [u8; 16],
}

fn scan_proc(comms: &HashSet<&str>) -> Result<Vec<Proc>> {
    let mut rst = vec![];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Ok(tgid) = name.parse::<u32>() {
            let comm = fs::read_to_string(path.join("comm"))?;
            let trimmed = comm.trim();
            if comms.contains(trimmed) {
                rst.push(Proc {
                    tgid: tgid as i32,
                    comm: null_terminated_array16_from_str(trimmed),
                });
            }
        }
    }
    Ok(rst)
}

fn null_terminated_array16_from_str(s: &str) -> [u8; 16] {
    let mut comm = [0; 16];
    comm[..s.len()].copy_from_slice(s.as_bytes());
    comm
}
