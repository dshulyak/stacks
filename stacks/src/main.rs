use std::{
    cell::RefCell,
    collections::HashSet,
    env,
    fmt::Write,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use bpf::{link, Profile, Programs, Rss, Switch};
use bpf_profile::Profiler;
use clap::{
    builder::{IntoResettable, Resettable, StyledStr},
    Parser,
};
use libbpf_rs::{Link, MapFlags, RingBufferBuilder};
use tracing::{error, info, info_span, level_filters::LevelFilter, warn};
use tracing_subscriber::{prelude::*, Registry};

use crate::{
    parquet::Compression,
    state::Received,
    symbolizer::{BlazesymSymbolizer, Frames, Symbolizer},
};

mod stacks {
    include!(concat!(env!("OUT_DIR"), "/stacks.skel.rs"));
}
use stacks::*;

mod bpf;
mod bpf_profile;
mod parquet;
mod perf_event;
mod state;
mod state_writer;
mod symbolizer;
#[cfg(test)]
mod tests;

// default correspond to profile:u:99,rss:u:29,switch:ku
const DEFAULT_PROGRAMS: Programs = Programs::new()
    .with_profile(Profile::new(bpf::Stacks::U, 99))
    .with_rss(Rss::new(bpf::Stacks::U, 29))
    .with_switch(Switch::new(bpf::Stacks::KU, 0));

fn default_path() -> PathBuf {
    let dir_wo_index = env::temp_dir().join("stacks");
    // go over all subdirectories, try to parse them as numbers pick 0 or last + 1
    let mut next = 0;
    if let Ok(entries) = fs::read_dir(&dir_wo_index) {
        for entry in entries {
            let entry = entry.expect("unable to read entry");
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    if let Some(name) = name.to_str() {
                        if let Ok(index) = name.parse::<u32>() {
                            next = next.max(index + 1);
                        }
                    }
                }
            }
        }
    }
    dir_wo_index.join(next.to_string())
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Opt {
    #[clap(
        num_args = 1..,
        required = true,
        help = "filter all threads of the process by the process command name. value in /proc/<pid>/comm"
    )]
    commands: Vec<String>,

    #[clap(short, long, default_value = default_path().into_os_string())]
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
        default_value_t = DEFAULT_PROGRAMS.clone(),
        help = ProgramsHelp{},
    )]
    programs: Programs,

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
        long,
        default_value = "false",
        help = "enable debug output for bpf program. it will be in /sys/kernel/debug/tracing/trace_pipe"
    )]
    debug_bpf: bool,

    #[clap(
        long,
        default_value = "30m",
        help = "output additional information about how much time is spent in bpf programs. it will be disabled if zero"
    )]
    profiling_interval: humantime::Duration,
}

fn main() -> Result<()> {
    let interrupt = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler({
        let interrupt = interrupt.clone();
        move || {
            interrupt.store(false, Ordering::Relaxed);
        }
    })?;

    let registry = Registry::default()
        .with(
            tracing_stacks::StacksSubscriber {}.with_filter(
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

    bump_memlock_rlimit()?;

    let opt: Opt = Opt::parse();
    let programs = opt.programs.clone();
    info!(
        "running bpf programs: {} for commands {}",
        programs,
        opt.commands.join(", ")
    );

    ensure_exists(&opt.dir)?;

    let uptime = parse_uptime()?;
    let current_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("current unix time")?;
    let adjustment = (current_unix - uptime).as_nanos() as u64;

    let (mut skel, mut links) = link(&programs, opt.debug_bpf, opt.bpf_events, opt.bpf_stacks)?;

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
    let frames = MapFrames(maps.stackmap());
    let cfg = state::Config {
        directory: opt.dir,
        timestamp_adjustment: adjustment,
        groups_per_file: opt.groups_per_file,
        rows_per_group: opt.rows,
        perf_event_frequency: 1_000_000_000 / programs.profile_frequency() as i64,
        compression: opt.compression,
        _non_exhaustive: (),
    };
    let (sender, receiver) = crossbeam::channel::bounded(4);

    let mut program = state::State::new(
        cfg,
        BlazesymSymbolizer::new(),
        sender,
    )?;
    for proc in procs.iter() {
        let fake_exec_event = stacks_types::process_exec_event {
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
    let mut profiler = if opt.profiling_interval.as_nanos() > 0 {
        Some(RefCell::new(Profiler::enable(opt.profiling_interval.into())?))
    } else {
        None
    };
    loop {
        match consume_events(
            &mut program,
            &maps,
            profiler.as_mut(),
            &progs,
            &mut dropped_counter,
            &interrupt,
            sleep_interval,
            &mut links,
        ) {
            Ok(_) => break,
            Err(ErrorConsume::DroppedEvents(dropped)) => {
                warn!("program missed events {}. will need to reinitialize state", dropped);
                let span = info_span!("reinitialize");
                let _guard = span.enter();
                program.drop_known_state()?;
                let scanned = scan_proc(&comms)?;
                for comm in scanned {
                    let fake_exec_event = stacks_types::process_exec_event {
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
    Ok(())
}

#[derive(thiserror::Error, Debug)]
enum ErrorConsume {
    #[error("ringbuf capacity can't handle events rate. dropped events since previous {0}")]
    DroppedEvents(u64),
    #[error(transparent)]
    LibbpfError(#[from] libbpf_rs::Error),
}

#[allow(clippy::too_many_arguments)]
fn consume_events(
    state: &mut state::State<impl Symbolizer>,
    maps: &StacksMaps,
    profiler: Option<&mut RefCell<Profiler>>,
    progs: &StacksProgs,
    dropped_counter: &mut u64,
    interrupt: &Arc<AtomicBool>,
    poll_interval: Duration,
    program_links: &mut Vec<Link>,
) -> Result<(), ErrorConsume> {
    let mut builder = RingBufferBuilder::new();
    builder.add(maps.events(), |buf: &[u8]| {
        let event: Received = match buf.try_into() {
            Ok(buf) => buf,
            Err(err) => {
                error!("invalid event: {:?}", err);
                return 1;
            }
        };
        if let Some(profiler) = &profiler {
            profiler.borrow_mut().collect(event.program_name());
        }
        if let Err(err) = state.on_event(event) {
            error!("non-recoverable error on event: {:?}", err);
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
                    info!("process was interrupted {:?}", err);
                } else {
                    warn!("consume from ring buffer: {:?}", err);
                }
            }
        });
        if !interrupt.load(Ordering::Relaxed) {
            info!("interrupted, dropping programs and consuming remaining events");
            program_links.clear();
            _ = mgr.consume();

            if let Some(profiler) = &profiler {
                if let Err(err) = profiler.borrow_mut().log_stats(progs) {
                    warn!("profiler failing to logs: {:?}", err);
                }
            }
            return Ok(());
        }
        let updated_dropped_counter = count_dropped_events(maps.errors_counter())?;
        if updated_dropped_counter > *dropped_counter {
            let delta = updated_dropped_counter - *dropped_counter;
            *dropped_counter = updated_dropped_counter;
            return Err(ErrorConsume::DroppedEvents(delta));
        }
        if let Some(profiler) = &profiler {
            if let Err(err) = profiler.borrow_mut().log_stats_on_interval(progs) {
                warn!("profiler failing to logs: {:?}", err);
            }
        }
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

// this value must match enum in stacks/src/bpf/stacks.h
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

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

struct ProgramsHelp {}

impl IntoResettable<StyledStr> for ProgramsHelp {
    fn into_resettable(self) -> Resettable<StyledStr> {
        let programs = Programs::default();
        let mut rst = String::new();
        writeln!(&mut rst, "{}", programs.help()).expect("no error");
        Resettable::Value(StyledStr::from(rst))
    }
}
