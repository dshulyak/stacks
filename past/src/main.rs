use core::time;
use std::{
    collections::HashSet,
    mem::MaybeUninit,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use libbpf_rs::{
    libbpf_sys::{PERF_COUNT_SW_CPU_CLOCK, PERF_TYPE_SOFTWARE},
    skel::{OpenSkel, SkelBuilder},
    MapFlags, RingBufferBuilder,
};
use tracing::{error, info, info_span, level_filters::LevelFilter, warn};
use tracing_subscriber::{prelude::*, Registry};

use crate::{
    collector::{BlazesymSymbolizer, Frames, Received, Symbolizer},
    parquet::Compression,
    perf_event::{attach_perf_event, perf_event_per_cpu},
    util::scan_proc,
};

mod past {
    include!(concat!(env!("OUT_DIR"), "/past.skel.rs"));
}
use past::*;

mod collector;
mod parquet;
mod perf_event;
mod program;
#[cfg(test)]
mod tests;
mod util;

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
        long,
        default_value = "1048576",
        help = "define size of the queue for all events. each event in the queue is 64 bytes"
    )]
    bpf_events: u32,

    #[clap(
        long,
        default_value = "131072",
        help = "define size of the bpf stack map. each item in the map is atmost 1016 bytes (127 items of 8 bytes each)"
    )]
    bpf_stacks: u32,

    #[clap(
        short,
        long,
        default_value = "100ms",
        help = "determines the frequency of polling the ebpf ring buffer"
    )]
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

    #[clap(long, default_value = "k", help = "which stacks to collect on context switch event")]
    switch_stacks: StackOptions,

    #[clap(long, default_value = "99")]
    perf_cpu_frequncy: u64,
    #[clap(long, default_value = "u", help = "which stacks to collect on perf event")]
    perf_cpu_stacks: StackOptions,

    #[clap(long, default_value = "u", help = "which stacks to collect when rss changes")]
    rss_stacks: StackOptions,
    #[clap(long, default_value = "0", help = "reduce number of emitted rss events. 0 disables throttling")]
    rss_throttle: u16,

    #[clap(long, default_value = "false", help = "print version and exit")]
    version: bool,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum StackOptions {
    U,
    K,
    UK,
    KU,
}

fn decode_stack_options_into_bpf_cfg(
    opts: &StackOptions,
    kstack: &mut MaybeUninit<bool>,
    ustack: &mut MaybeUninit<bool>,
) {
    match opts {
        StackOptions::U => {
            kstack.write(false);
            ustack.write(true);
        }
        StackOptions::K => {
            kstack.write(true);
            ustack.write(false);
        }
        StackOptions::UK | StackOptions::KU => {
            kstack.write(true);
            ustack.write(true);
        }
    }
}

fn main() -> Result<()> {
    let opt: Opt = Opt::parse();
    if opt.version {
        println!("past {}", env!("VERSION"));
        return Ok(());
    }
    if opt.commands.is_empty() {
        anyhow::bail!("at least one command must be provided");
    }

    // the levels for fmt and past subscriber are intentionally different.
    // i want to collect latency for basic operations all the time to evaluate performance
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
                    .with_default_directive(LevelFilter::WARN.into())
                    .from_env_lossy(),
            ),
        );
    tracing::dispatcher::set_global_default(registry.into()).expect("failed to set global default subscriber");

    let interrupt = Arc::new(AtomicBool::new(true));
    let interrupt_handler = interrupt.clone();
    ctrlc::set_handler(move || {
        interrupt_handler.store(false, Ordering::Relaxed);
    })?;

    util::ensure_exists(&opt.dir)?;

    let uptime = util::parse_uptime()?;
    let current_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("current unix time")?;
    let adjustment = (current_unix - uptime).as_nanos() as u64;

    let skel_builder = PastSkelBuilder::default();
    let mut open_skel = skel_builder.open().unwrap();
    let cfg = &mut open_skel.rodata_mut().cfg;
    cfg.filter_tgid.write(true);
    cfg.filter_comm.write(true);
    cfg.debug.write(opt.debug_bpf);
    cfg.rss_stat_throttle = opt.rss_throttle;

    decode_stack_options_into_bpf_cfg(&opt.switch_stacks, &mut cfg.switch_kstack, &mut cfg.switch_ustack);
    decode_stack_options_into_bpf_cfg(&opt.perf_cpu_stacks, &mut cfg.perf_kstack, &mut cfg.perf_ustack);
    decode_stack_options_into_bpf_cfg(&opt.rss_stacks, &mut cfg.rss_kstack, &mut cfg.rss_ustack);

    open_skel
        .maps_mut()
        .events()
        .set_max_entries(64 * opt.bpf_events)
        .unwrap();
    open_skel.maps_mut().stackmap().set_max_entries(opt.bpf_stacks).unwrap();

    let mut skel = open_skel.load().unwrap();

    let perf_fds = perf_event_per_cpu(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, opt.perf_cpu_frequncy)
        .expect("init perf events");
    let _perf_links = attach_perf_event(&perf_fds, skel.progs_mut().handle__perf_event());
    let _sched_link = skel
        .progs_mut()
        .handle__sched_switch()
        .attach()
        .expect("attach sched switch");
    let _sched_exit_link = skel
        .progs_mut()
        .handle__sched_process_exit()
        .attach()
        .expect("attach sched exit");
    let _sched_exec_link = skel
        .progs_mut()
        .handle__sched_process_exec()
        .attach()
        .expect("attach sched exec");
    let _rss_stat_link = skel
        .progs_mut()
        .handle__mm_trace_rss_stat()
        .attach()
        .expect("attach mm_trace_rss_stat");

    let mut _usdt_links = vec![];
    for u in opt.usdt.iter() {
        let _usdt_enter = skel
            .progs_mut()
            .past_tracing_enter()
            .attach_usdt(-1, u, "past_tracing", "enter")
            .expect("i hope -1 works");
        let _usdt_exit = skel
            .progs_mut()
            .past_tracing_exit()
            .attach_usdt(-1, u, "past_tracing", "exit")
            .expect("i hope -1 works");
        let _usdt_exit_stack = skel
            .progs_mut()
            .past_tracing_exit_stack()
            .attach_usdt(-1, u, "past_tracing", "exit_stack")
            .expect("exit stack link");
        let _usdt_close = skel
            .progs_mut()
            .past_tracing_close()
            .attach_usdt(-1, u, "past_tracing", "close")
            .expect("i hope -1 works");
        _usdt_links.push(_usdt_enter);
        _usdt_links.push(_usdt_exit);
        _usdt_links.push(_usdt_exit_stack);
        _usdt_links.push(_usdt_close);
    }

    let zero: u8 = 0;
    for comm in opt.commands.iter() {
        let comm = util::Comm::from(comm.as_str());
        let comm = *comm;
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
    let mut program = program::Program::new(
        program::Config {
            directory: opt.dir,
            timestamp_adjustment: adjustment,
            groups_per_file: opt.groups_per_file,
            rows_per_group: opt.rows,
            perf_event_frequency: 1_000_000_000 / opt.perf_cpu_frequncy as i64,
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
            comm: *proc.comm,
            ..Default::default()
        };
        program.on_event(Received::ProcessExec(&fake_exec_event))?;
    }

    let mut dropped_counter = 0;
    let sleep_interval = opt.poll.into();
    loop {
        match consume_events(&mut program, &maps, &mut dropped_counter, &interrupt, sleep_interval) {
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
                        comm: *comm.comm,
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
    program: &mut program::Program<Fr, Sym>,
    maps: &PastMaps,
    dropped_counter: &mut u64,
    interrupt: &Arc<AtomicBool>,
    sleep_interval: time::Duration,
) -> Result<(), ErrorConsume> {
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
            if let Err(err) = mgr.consume() {
                warn!("consume from ring buffer: {:?}", err);
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
        sleep(sleep_interval);
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

// this value must match enum in  past/src/bpf/past.h
// i need to lookup how to generate bindings for enums
const DROPPED_EVENTS: u32 = 0;

fn count_dropped_events(errors_counter: &libbpf_rs::Map) -> Result<u64, libbpf_rs::Error> {
    let key = DROPPED_EVENTS.to_ne_bytes();
    let rst = errors_counter.lookup_percpu(&key, MapFlags::empty())?;
    if let Some(rst) = rst {
        let mut sum = 0;
        for cpu in rst.iter() {
            sum += u64::from_ne_bytes(cpu.as_slice().try_into().expect("events counter must be 8 bytes long"));
        }
        Ok(sum)
    } else {
        Ok(0)
    }
}
