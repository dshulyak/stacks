use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap, HashSet},
    io::Write,
    iter::empty,
    num::NonZeroU32,
};

use anyhow::Result;
use blazesym::symbolize::{self, Input, Kernel, Process, Source, Symbolized};
use bytes::{Bytes, BytesMut};
use plain::Plain;
use tracing::debug;

use crate::{
    parquet::{Event, Group, GroupWriter},
    past::past_types,
};

unsafe impl Plain for past_types::switch_event {}
unsafe impl Plain for past_types::perf_cpu_event {}
unsafe impl Plain for past_types::tracing_enter_event {}
unsafe impl Plain for past_types::tracing_exit_event {}
unsafe impl Plain for past_types::tracing_close_event {}
unsafe impl Plain for past_types::process_exit_event {}
unsafe impl Plain for past_types::process_exec_event {}

#[cfg(test)]
pub(crate) fn to_bytes<T: Plain>(event: &T) -> &[u8] {
    unsafe { plain::as_bytes(event) }
}

fn to_event<T: Plain>(bytes: &[u8]) -> &T {
    plain::from_bytes(bytes).expect("failed to convert bytes to event")
}

#[derive(Debug, Clone)]
pub(crate) enum Received<'a> {
    Switch(&'a past_types::switch_event),
    PerfStack(&'a past_types::perf_cpu_event),
    ProcessExec(&'a past_types::process_exec_event),
    ProcessExit(&'a past_types::process_exit_event),
    TraceEnter(&'a past_types::tracing_enter_event),
    TraceExit(&'a past_types::tracing_exit_event),
    TraceClose(&'a past_types::tracing_close_event),
    Unknown(&'a [u8]),
}

impl<'a> From<&'a [u8]> for Received<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        match bytes[0] {
            0 => Received::Switch(to_event(bytes)),
            1 => Received::PerfStack(to_event(bytes)),
            2 => Received::TraceEnter(to_event(bytes)),
            3 => Received::TraceExit(to_event(bytes)),
            4 => Received::TraceClose(to_event(bytes)),
            5 => Received::ProcessExit(to_event(bytes)),
            6 => Received::ProcessExec(to_event(bytes)),
            _ => Received::Unknown(bytes),
        }
    }
}

#[derive(Debug)]
struct SpanEnter {
    parent_id: u64,
    work_id: u64,
    amount: u64,
    name: Bytes,
    first_enter_ts: u64,
    last_enter_ts: u64,
}

pub(crate) struct Collector {
    tgid_to_command: HashMap<u32, Bytes>,
    tgid_span_id_pid_to_enter: BTreeMap<(u32, u64, u32), SpanEnter>,
    pub group: Group,
}

impl Collector {
    pub(crate) fn new(group: Group) -> Self {
        Self {
            tgid_to_command: HashMap::new(),
            tgid_span_id_pid_to_enter: BTreeMap::new(),
            group,
        }
    }

    pub(crate) fn collect(&mut self, event: Received) -> Result<()> {
        // all integers are cast to a signed form because of the API provided by rust parquet lib
        // arithmetic operations will be correctly performed on unsigned integers, configured in schema
        // TODO maybe i should move cast closer to the schema definition

        match event {
            Received::Switch(event) => {
                let command = match self.tgid_to_command.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", event.tgid);
                    }
                };
                self.group.collect(Event::Switch {
                    ts: event.end as i64,
                    duration: (event.end - event.start) as i64,
                    cpu: event.cpu_id as i32,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: command.clone(),
                    ustack: event.ustack,
                    kstack: event.kstack,
                });
            }
            Received::PerfStack(event) => {
                if event.ustack > 0 || event.kstack > 0 {
                    let command = match self.tgid_to_command.get(&event.tgid) {
                        Some(command) => command,
                        None => {
                            anyhow::bail!("missing command for pid {}", event.tgid);
                        }
                    };
                    self.group.collect(Event::CPUStack {
                        ts: event.timestamp as i64,
                        cpu: event.cpu_id as i32,
                        tgid: event.tgid as i32,
                        pid: event.pid as i32,
                        command: command.clone(),
                        ustack: event.ustack,
                        kstack: event.kstack,
                    });
                };
            }
            Received::TraceEnter(event) => {
                let entry = self
                    .tgid_span_id_pid_to_enter
                    .entry((event.tgid, event.span_id, event.pid));
                match entry {
                    btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(SpanEnter {
                            parent_id: event.parent_id,
                            work_id: event.work_id,
                            amount: event.amount,
                            name: Bytes::copy_from_slice(null_terminated(&event.name)),
                            first_enter_ts: event.ts,
                            last_enter_ts: event.ts,
                        });
                    }
                    btree_map::Entry::Occupied(mut occupied) => {
                        let span = occupied.get_mut();
                        span.last_enter_ts = event.ts;
                    }
                };
            }
            Received::TraceExit(event) => {
                let command = match self.tgid_to_command.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", event.tgid);
                    }
                };
                let span = match self
                    .tgid_span_id_pid_to_enter
                    .get(&(event.tgid, event.span_id, event.pid))
                {
                    Some(span) => span,
                    None => {
                        anyhow::bail!("missing span for pid {} span_id {}", event.pid, event.span_id);
                    }
                };
                self.group.collect(Event::TraceExit {
                    ts: event.ts as i64,
                    duration: (event.ts - span.last_enter_ts) as i64,
                    cpu: event.cpu_id as i32,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: command.clone(),
                    span_id: event.span_id as i64,
                    parent_id: span.parent_id as i64,
                    work_id: span.work_id as i64,
                    amount: span.amount as i64,
                    name: span.name.clone(),
                    ustack: event.ustack,
                });
            }
            Received::TraceClose(event) => {
                // record it only once for any pid where this span_id has entered before
                let pids = self
                    .tgid_span_id_pid_to_enter
                    .range((event.tgid, event.span_id, 0)..(event.tgid, event.span_id, u32::MAX))
                    .map(|(k, _)| k.2)
                    .collect::<Vec<_>>();
                let command = self.tgid_to_command.get(&pids[0]);
                for (i, pid) in pids.into_iter().enumerate() {
                    let span = match self.tgid_span_id_pid_to_enter.remove(&(event.tgid, event.span_id, pid)) {
                        Some(span) => span,
                        None => {
                            anyhow::bail!("missing span for pid {} span_id {}", pid, event.span_id);
                        }
                    };
                    if i > 0 {
                        continue;
                    }
                    if let Some(command) = command {
                        self.group.collect(Event::TraceClose {
                            ts: event.ts as i64,
                            duration: (event.ts - span.first_enter_ts) as i64,
                            cpu: event.cpu_id as i32,
                            tgid: event.tgid as i32,
                            pid: pid as i32,
                            command: command.clone(),
                            span_id: event.span_id as i64,
                            parent_id: span.parent_id as i64,
                            work_id: span.work_id as i64,
                            amount: span.amount as i64,
                            name: span.name.clone(),
                        });
                    }
                }
            }
            Received::ProcessExec(event) => {
                let _ = command(&mut self.tgid_to_command, event.tgid, &event.comm);
            }
            Received::ProcessExit(event) => {
                self.tgid_to_command.remove(&event.tgid);
                let entries = self
                    .tgid_span_id_pid_to_enter
                    .range((event.tgid, 0, 0)..(event.tgid, u64::MAX, u32::MAX))
                    .map(|(k, _)| (k.1, k.2))
                    .collect::<Vec<_>>();
                for (span_id, pid) in entries {
                    self.tgid_span_id_pid_to_enter.remove(&(event.tgid, span_id, pid));
                }
            }
            Received::Unknown(event) => {
                anyhow::bail!("unknown event type: {:?}", event);
            }
        }
        Ok(())
    }
}

fn command(commands: &mut HashMap<u32, Bytes>, tgid: u32, command: &[u8]) -> Bytes {
    let comm = null_terminated(command);
    let existing = commands.entry(tgid);
    match existing {
        hash_map::Entry::Vacant(vacant) => vacant.insert(Bytes::copy_from_slice(comm)).clone(),
        hash_map::Entry::Occupied(mut occupied) => {
            if occupied.get() != comm {
                occupied.insert(Bytes::copy_from_slice(comm));
            }
            occupied.get().clone()
        }
    }
}

pub(crate) fn null_terminated(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

pub(crate) fn on_symbolize(
    stack_group: &mut Group,
    stacks: &impl Frames,
    symbolizer: &mut impl Symbolizer,
) -> Result<()> {
    symbolize(symbolizer, stacks, stack_group);
    stack_group.reuse_unresolved();
    Ok(())
}

pub(crate) fn on_exit<W: Write + Send>(
    mut stack_writer: GroupWriter<W>,
    stack_group: &mut Group,
    symbolizer: &impl Symbolizer,
    stacks: &impl Frames,
) -> Result<()> {
    if !stack_group.is_empty() {
        symbolize(symbolizer, stacks, stack_group);
        stack_writer.write(stack_group)?;
        stack_group.reuse();
    }
    stack_writer.close()?;
    Ok(())
}

pub(crate) trait Frames {
    fn frames(&self, id: i32) -> Result<Vec<u64>>;
}

fn symbolize(symbolizer: &impl Symbolizer, stacks: &impl Frames, stack_group: &mut Group) {
    let mut addresses: HashMap<(i32, u64), Bytes> = HashMap::new();
    let kstacks: HashSet<_> = stack_group.unresolved_kstacks().collect();
    let mut unique = HashSet::new();
    let traces: HashMap<i32, Result<Vec<u64>>> = kstacks
        .into_iter()
        .filter(|&stack_id| stack_id > 0)
        .map(|stack_id| {
            let trace = stacks.frames(stack_id);
            match &trace {
                Ok(trace) => {
                    for &frame in trace {
                        unique.insert(frame);
                    }
                }
                Err(err) => {
                    debug!("frames: {}", err);
                }
            }
            (stack_id, trace)
        })
        .collect();
    let req = unique.into_iter().collect::<Vec<_>>();
    let symbols = match symbolizer.kernel_symbolize(&req) {
        Ok(syms) => syms,
        Err(err) => {
            debug!("symbolize: {}", err);
            return;
        }
    };
    for (symbol, addr) in symbols.into_iter().zip(req.into_iter()) {
        if let Some(sym) = symbol.as_sym() {
            addresses.insert((-1, addr), Bytes::copy_from_slice(sym.name.as_bytes()));
        }
    }

    let mut ustack_traces = HashMap::new();
    let mut ustacks = HashMap::new();
    for (tgid, ustack) in stack_group.unresolved_ustacks() {
        let ustacks = ustacks.entry(tgid).or_insert_with(HashSet::new);
        ustacks.insert(ustack);
    }
    let mut unique = HashMap::new();
    for (tgid, ustack) in ustacks.into_iter() {
        for stack_id in ustack.into_iter().filter(|&stack_id| stack_id > 0) {
            let trace = stacks.frames(stack_id);
            match &trace {
                Ok(trace) => {
                    for &frame in trace {
                        unique.entry(tgid).or_insert_with(HashSet::new).insert(frame);
                    }
                }
                Err(err) => {
                    debug!("frames: {}", err);
                }
            }
            ustack_traces.insert(stack_id, trace);
        }
    }

    for (tgid, addrs) in unique {
        let req = addrs.into_iter().collect::<Vec<_>>();
        let symbols = match symbolizer.user_symbolize(tgid, &req) {
            Ok(syms) => syms,
            Err(err) => {
                debug!("symbolize: tgid={} err={}", tgid, err);
                continue;
            }
        };
        for (symbol, addr) in symbols.into_iter().zip(req.into_iter()) {
            if let Some(sym) = symbol.as_sym() {
                let name = sym.name.as_bytes();
                let offset = sym.offset.to_string();
                let offset: &[u8] = offset.as_bytes();
                let mut buf = BytesMut::with_capacity(name.len() + offset.len() + 1);
                buf.extend_from_slice(name);
                if sym.offset > 0 {
                    buf.extend_from_slice(b"+");
                    buf.extend_from_slice(offset);
                }
                addresses.insert((tgid, addr), buf.into());
            }
        }
    }

    let original_kstacks = stack_group.unresolved_kstacks().collect::<Vec<_>>();
    let original_ustacks = stack_group.unresolved_ustacks().collect::<Vec<_>>();

    let zipped = original_kstacks.into_iter().zip(original_ustacks);
    for (kstack_id, (tgid, ustack_id)) in zipped {
        match (
            to_symbols(&ustack_traces, &addresses, tgid, ustack_id),
            to_symbols(&traces, &addresses, -1, kstack_id),
        ) {
            (Some(ustacks), Some(kstacks)) => {
                stack_group.resolve(ustacks, kstacks);
            }
            (Some(ustacks), None) => {
                stack_group.resolve(ustacks, empty());
            }
            (None, Some(kstacks)) => {
                stack_group.resolve(empty(), kstacks);
            }
            (None, None) => {
                stack_group.resolve(empty(), empty());
            }
        }
    }
}

fn to_symbols<'a>(
    traces: &'a HashMap<i32, Result<Vec<u64>>>,
    addresses: &'a HashMap<(i32, u64), Bytes>,
    tgid: i32,
    stack_id: i32,
) -> Option<impl Iterator<Item = Bytes> + 'a> {
    stack_id.checked_sub(1).and_then(move |stack_id| {
        traces.get(&(stack_id + 1)).and_then(move |trace| {
            trace.as_ref().ok().map(move |trace| {
                trace
                    .iter()
                    .filter(|frame| **frame > 0)
                    .flat_map(move |&frame| addresses.get(&(tgid, frame)).cloned())
            })
        })
    })
}

pub(crate) trait Symbolizer {
    fn new() -> Self;

    fn reset(&mut self);

    fn kernel_symbolize(&self, addr: &[u64]) -> Result<Vec<Symbolized>, anyhow::Error>;

    fn cache_tgid(&mut self, tgid: i32, ustack: i64, frames: &impl Frames) -> Result<(), anyhow::Error>;

    fn user_symbolize(&self, pid: i32, addr: &[u64]) -> Result<Vec<Symbolized>, anyhow::Error>;
}

pub(crate) struct BlazesymSymbolizer {
    symbolizer: symbolize::Symbolizer,
    tried: HashSet<i32>,
}

impl Symbolizer for BlazesymSymbolizer {
    fn new() -> Self {
        Self {
            symbolizer: symbolize::Symbolizer::builder().enable_auto_reload(false).build(),
            tried: HashSet::new(),
        }
    }

    fn reset(&mut self) {
        self.symbolizer = symbolize::Symbolizer::builder().enable_auto_reload(false).build();
        self.tried = HashSet::new();
    }

    fn kernel_symbolize(&self, addr: &[u64]) -> Result<Vec<Symbolized>, anyhow::Error> {
        let rst = self
            .symbolizer
            .symbolize(&Source::Kernel(Kernel::default()), Input::AbsAddr(addr))?;
        Ok(rst)
    }

    fn cache_tgid(&mut self, tgid: i32, ustack: i64, _frames: &impl Frames) -> Result<(), anyhow::Error> {
        if ustack <= 0 {
            return Ok(());
        }
        if self.tried.contains(&tgid) {
            return Ok(());
        }
        debug!("cache_tgid: symbolizing tgid={}", tgid);
        self.tried.insert(tgid);
        let rst = self.symbolizer.symbolize(
            &Source::Process(Process {
                pid: blazesym::Pid::Pid(NonZeroU32::new(tgid as u32).unwrap()),
                debug_syms: false,
                perf_map: false,
                map_files: true,
                _non_exhaustive: (),
            }),
            Input::AbsAddr(&[]),
        );
        match rst {
            Ok(_) => {
                debug!("cache_tgid: success symbolized tgid={}", tgid);
            }
            Err(err) => {
                debug!("cache_tgid: failure symbolized tgid={} err={}", tgid, err);
            }
        }
        Ok(())
    }

    fn user_symbolize(&self, pid: i32, addr: &[u64]) -> Result<Vec<Symbolized>, anyhow::Error> {
        let rst = self.symbolizer.symbolize(
            &Source::Process(Process {
                pid: blazesym::Pid::Pid(NonZeroU32::new(pid as u32).unwrap()),
                debug_syms: true,
                perf_map: false,
                map_files: true,
                _non_exhaustive: (),
            }),
            Input::AbsAddr(addr),
        )?;
        Ok(rst)
    }
}
