use std::{
    collections::HashSet,
    io::Write,
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
use tracing::{debug, error, info, info_span, instrument, level_filters::LevelFilter, warn};
use tracing_subscriber::{prelude::*, Registry};

use crate::{
    collector::{on_symbolize, BlazesymSymbolizer, Collector, Frames, Received, Symbolizer},
    parquet::{Compression, GroupWriter},
    perf_event::perf_event_per_cpu,
    util::scan_proc,
};

mod past {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/past.skel.rs"));
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
        num_args = 1.., required = true,
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
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum StackOptions {
    U,
    K,
    UK,
    KU,
}

fn main() -> Result<()> {
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
        .with(tracing_subscriber::fmt::layer().with_filter(tracing_subscriber::EnvFilter::from_default_env()));
    tracing::dispatcher::set_global_default(registry.into()).expect("failed to set global default subscriber");

    let interrupt = Arc::new(AtomicBool::new(true));
    let interrupt_handler = interrupt.clone();
    ctrlc::set_handler(move || {
        interrupt_handler.store(false, Ordering::Relaxed);
    })?;

    let opt: Opt = Opt::parse();
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
    match opt.switch_stacks {
        StackOptions::U => {
            cfg.switch_kstack.write(false);
            cfg.switch_ustack.write(true);
        }
        StackOptions::K => {
            cfg.switch_kstack.write(true);
            cfg.switch_ustack.write(false);
        }
        StackOptions::UK | StackOptions::KU => {
            cfg.switch_kstack.write(true);
            cfg.switch_ustack.write(true);
        }
    }
    match opt.perf_cpu_stacks {
        StackOptions::U => {
            cfg.perf_kstack.write(false);
            cfg.perf_ustack.write(true);
        }
        StackOptions::K => {
            cfg.perf_kstack.write(true);
            cfg.perf_ustack.write(false);
        }
        StackOptions::UK | StackOptions::KU => {
            cfg.perf_kstack.write(true);
            cfg.perf_ustack.write(true);
        }
    }

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
        let comm = util::Comm::from(comm);
        let comm = *comm;
        skel.maps_mut()
            .filter_comm()
            .update(&comm, &zero.to_ne_bytes(), MapFlags::ANY)?;
    }
    let comms = opt.commands.iter().map(|c| c.as_str()).collect::<HashSet<_>>();
    scan_proc(comms, &mut MapsTgidIndex(skel.maps_mut().filter_tgid()))?;

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
    {
        let mut builder = RingBufferBuilder::new();
        builder.add(maps.events(), |buf: &[u8]| {
            if let Err(err) = program.on_event(buf) {
                error!("failed to process event: {:?}", err);
                1
            } else {
                0
            }
        })?;

        let mgr = builder.build().unwrap();
        let interval = opt.poll.into();
        let consume = info_span!("consume");
        while interrupt.load(Ordering::Relaxed) {
            consume.in_scope(|| {
                if let Err(err) = mgr.consume() {
                    warn!("consume from ring buffer: {:?}", err);
                }
            });
            sleep(interval);
        }
    }
    info!("trace interrupted, flushing pending data to file and exiting");
    program.exit()
}

struct MapFrames<'a>(&'a libbpf_rs::Map);

impl Frames for MapFrames<'_> {
    fn frames(&self, id: i64) -> Result<Vec<u64>> {
        let id = (id as u32).to_ne_bytes();
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

struct MapsTgidIndex<'a>(&'a mut libbpf_rs::Map);

impl util::TgidIndex for MapsTgidIndex<'_> {
    fn insert(&mut self, key: u32) -> anyhow::Result<()> {
        let buf = key.to_ne_bytes();
        self.0.update(&buf, &[0], MapFlags::empty())?;
        Ok(())
    }
}

fn attach_perf_event(pefds: &[i32], prog: &mut libbpf_rs::Program) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds.iter().map(|pefd| prog.attach_perf_event(*pefd)).collect()
}

fn on_event<W: Write + Send>(
    stack_writer: &mut GroupWriter<W>,
    stacks: &impl Frames,
    collector: &mut Collector,
    symbolizer: &mut impl Symbolizer,
    event: &[u8],
) -> Result<()> {
    record(collector, symbolizer, stacks, event.into());
    if collector.group.is_full() {
        debug!("flushing stacks to disk");
        symbolize(collector, stacks, symbolizer)?;
        flush_group(stack_writer, collector)?;
        collector.group.reuse();
        debug!("flushed stacks to disk");
    }
    Ok(())
}

#[instrument(skip_all)]
fn flush_group<W: Write + Send>(stack_writer: &mut GroupWriter<W>, collector: &mut Collector) -> Result<()> {
    stack_writer.write(&collector.group)
}

#[instrument(skip_all)]
fn symbolize(collector: &mut Collector, stacks: &impl Frames, symbolizer: &mut impl Symbolizer) -> Result<()> {
    on_symbolize(&mut collector.group, stacks, symbolizer)
}

fn record(collector: &mut Collector, symbolizer: &mut impl Symbolizer, frames: &impl Frames, buf: Received) {
    match buf {
        Received::Switch(event) => {
            if event.kstack > 0 || event.ustack > 0 {
                symbolizer
                    .cache_tgid(event.tgid as i32, event.ustack as i64, frames)
                    .unwrap();
            }
        }
        Received::Perf(event) => {
            if event.kstack > 0 || event.ustack > 0 {
                symbolizer
                    .cache_tgid(event.tgid as i32, event.ustack as i64, frames)
                    .unwrap();
            }
        }
        _ => {}
    };
    if let Err(err) = collector.collect(buf) {
        warn!("failed to collect event: {:?}", err);
    }
}
