use std::{
    collections::{btree_map, BTreeMap, HashMap, HashSet},
    fs,
    iter::empty,
    num::NonZeroU32,
    rc::Rc,
    time::SystemTime,
};

use anyhow::Result;
use blazesym::symbolize::{self, Input, Kernel, Process, Source, Symbolized};
use bytes::Bytes;
use plain::Plain;
use tracing::{debug, instrument, warn};

use crate::{
    parquet::{Event, Group, ResolvedStack},
    past::past_types,
};

unsafe impl Plain for past_types::switch_event {}
unsafe impl Plain for past_types::perf_cpu_event {}
unsafe impl Plain for past_types::tracing_enter_event {}
unsafe impl Plain for past_types::tracing_exit_event {}
unsafe impl Plain for past_types::tracing_close_event {}
unsafe impl Plain for past_types::process_exit_event {}
unsafe impl Plain for past_types::process_exec_event {}
unsafe impl Plain for past_types::rss_stat_event {}

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
    RssStat(&'a past_types::rss_stat_event),
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
            7 => Received::RssStat(to_event(bytes)),
            _ => Received::Unknown(bytes),
        }
    }
}

#[derive(Debug)]
struct SpanEnter {
    parent_id: u64,
    id: u64,
    amount: u64,
    name: Bytes,
    first_enter_ts: u64,
    last_enter_ts: u64,
}

pub(crate) struct Collector {
    tgid_span_id_pid_to_enter: BTreeMap<(u32, u64, u32), SpanEnter>,
    pub group: Group,
    page_size: u64,
}

impl Collector {
    pub(crate) fn new(group: Group, page_size: u64) -> Self {
        Self {
            tgid_span_id_pid_to_enter: BTreeMap::new(),
            group,
            page_size,
        }
    }

    pub(crate) fn drop_known_spans(&mut self) {
        self.tgid_span_id_pid_to_enter.clear();
    }

    pub(crate) fn collect(&mut self, tgid_to_command: &HashMap<u32, Bytes>, event: Received) -> Result<()> {
        // all integers are cast to signed because of the API provided by rust parquet lib
        // arithmetic operations will be correctly performed on unsigned integers, configured in schema
        // TODO maybe i should move cast closer to the schema definition
        match event {
            Received::Switch(event) => {
                let command = match tgid_to_command.get(&event.tgid) {
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
                    let command = match tgid_to_command.get(&event.tgid) {
                        Some(command) => command,
                        None => {
                            anyhow::bail!("missing command for tgid {}", event.tgid);
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
            Received::RssStat(event) => {
                let command = match tgid_to_command.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for tgid {}", event.tgid);
                    }
                };
                self.group.collect(Event::RssStat {
                    ts: event.ts as i64,
                    tgid: event.tgid as i32,
                    command: command.clone(),
                    amount: event.rss * self.page_size,
                    ustack: event.ustack,
                    kstack: event.kstack,
                });
            }
            Received::TraceEnter(event) => {
                let entry = self
                    .tgid_span_id_pid_to_enter
                    .entry((event.tgid, event.span_id, event.pid));
                match entry {
                    btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(SpanEnter {
                            parent_id: event.parent_id,
                            id: event.id,
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
                let command = match tgid_to_command.get(&event.tgid) {
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
                    id: span.id as i64,
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
                let command = tgid_to_command.get(&pids[0]);
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
                            id: span.id as i64,
                            amount: span.amount as i64,
                            name: span.name.clone(),
                        });
                    }
                }
            }
            Received::ProcessExec(_) => {}
            Received::ProcessExit(event) => {
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

pub(crate) fn null_terminated(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

pub(crate) trait Frames {
    fn frames(&self, id: i32) -> Result<Vec<u64>>;
}

#[instrument(skip_all)]
pub(crate) fn symbolize(symbolizer: &impl Symbolizer, stacks: &impl Frames, stack_group: &mut Group) {
    let mut resolved_addresses: HashMap<(i32, u64), ResolvedStack> = HashMap::new();
    let kstacks: HashSet<_> = stack_group.unresolved_kstacks().collect();
    let mut unique = HashSet::new();
    let traces: HashMap<i32, Result<Vec<u64>>> = kstacks
        .into_iter()
        .filter(|&stack_id| stack_id >= 0)
        .map(|stack_id| {
            let trace = stacks.frames(stack_id);
            match &trace {
                Ok(trace) => {
                    for &frame in trace {
                        unique.insert(frame);
                    }
                }
                Err(err) => {
                    debug!("collecting kernel frames. stack = {} error = {}", stack_id, err);
                }
            }
            (stack_id, trace)
        })
        .collect();
    let req = unique.into_iter().collect::<Vec<_>>();
    match symbolizer.symbolize_kernel(&req) {
        Ok(syms) => {
            for (symbol, addr) in syms.into_iter().zip(req.into_iter()) {
                if let Some(sym) = symbol.as_sym() {
                    let stack =
                        ResolvedStack::new(Bytes::copy_from_slice(sym.name.as_bytes()), sym.addr, sym.offset as u64);
                    resolved_addresses.insert((-1, addr), stack);
                }
            }
        }
        Err(err) => {
            warn!("symbolize kernel addresses: {}", err);
        }
    };

    let mut ustack_traces = HashMap::new();
    let mut ustacks = HashMap::new();
    for (tgid, ustack) in stack_group.unresolved_ustacks() {
        let ustacks = ustacks.entry(tgid).or_insert_with(HashSet::new);
        ustacks.insert(ustack);
    }
    let mut unique = HashMap::new();
    for (tgid, ustack) in ustacks.into_iter() {
        for stack_id in ustack.into_iter().filter(|&stack_id| stack_id >= 0) {
            let trace = stacks.frames(stack_id);
            match &trace {
                Ok(trace) => {
                    for &frame in trace {
                        unique.entry(tgid).or_insert_with(HashSet::new).insert(frame);
                    }
                }
                Err(err) => {
                    debug!("collecting user frames. stack = {} err = {}", stack_id, err);
                }
            }
            ustack_traces.insert(stack_id, trace);
        }
    }

    for (tgid, addrs) in unique {
        let req = addrs.into_iter().collect::<Vec<_>>();
        let symbols = match symbolizer.symbolize_process(tgid as u32, &req) {
            Ok(syms) => syms,
            Err(err) => {
                debug!("symbolizing process {}: {}", tgid, err);
                continue;
            }
        };
        for (symbol, addr) in symbols.into_iter().zip(req.into_iter()) {
            if let Some(sym) = symbol.as_sym() {
                let stack =
                    ResolvedStack::new(Bytes::copy_from_slice(sym.name.as_bytes()), sym.addr, sym.offset as u64);
                resolved_addresses.insert((tgid, addr), stack);
            }
        }
    }

    let original_kstacks = stack_group.unresolved_kstacks().collect::<Vec<_>>();
    let original_ustacks = stack_group.unresolved_ustacks().collect::<Vec<_>>();

    let zipped = original_kstacks.into_iter().zip(original_ustacks);
    for (kstack_id, (tgid, ustack_id)) in zipped {
        match (
            to_symbols(&ustack_traces, &resolved_addresses, tgid, ustack_id),
            to_symbols(&traces, &resolved_addresses, -1, kstack_id),
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
    addresses: &'a HashMap<(i32, u64), ResolvedStack>,
    tgid: i32,
    stack_id: i32,
) -> Option<impl Iterator<Item = &'a ResolvedStack> + 'a> {
    stack_id.checked_sub(1).and_then(move |stack_id| {
        traces.get(&(stack_id + 1)).and_then(move |trace| {
            trace.as_ref().ok().map(move |trace| {
                trace
                    .iter()
                    .filter(|frame| **frame > 0)
                    .flat_map(move |&frame| addresses.get(&(tgid, frame)))
            })
        })
    })
}

pub(crate) trait Symbolizer {
    fn new() -> Self;

    fn symbolize_kernel(&self, addr: &[u64]) -> Result<Vec<Symbolized>>;

    fn init_symbolizer(&mut self, tgid: u32) -> Result<()>;

    fn drop_symbolizer(&mut self, tgid: u32) -> Result<()>;

    fn symbolize_process(&self, tgid: u32, addr: &[u64]) -> Result<Vec<Symbolized>>;
}

#[derive(Debug)]
struct ExecutableSymbolizer {
    symbolizer: symbolize::Symbolizer,
    exe: String,
    mtime: u64,
}

pub(crate) struct BlazesymSymbolizer {
    // kernel_symbolizer can be reused for the whole lifetime of the program,
    // technically it is exactly same object as any other symbolizer, but it will not cache any userspace files for
    // symbolizations
    kernel_symbolizer: symbolize::Symbolizer,
    // symbolizers for userspace data have to live until:
    // - all processes that use referenced executable exited
    // - last batch of frames are symbolized after last process that used them exited
    // (if i drop symbolizer immediately data will be lost)
    executable_symbolizers: HashMap<(String, u64), Rc<ExecutableSymbolizer>>,
    process_symbolizers: HashMap<u32, Rc<ExecutableSymbolizer>>,
}

impl Symbolizer for BlazesymSymbolizer {
    fn new() -> Self {
        Self {
            kernel_symbolizer: symbolize::Symbolizer::builder()
                .enable_code_info(false)
                .enable_inlined_fns(false)
                .enable_auto_reload(false)
                .build(),
            executable_symbolizers: HashMap::new(),
            process_symbolizers: HashMap::new(),
        }
    }

    fn symbolize_kernel(&self, addr: &[u64]) -> Result<Vec<Symbolized>> {
        let rst = self
            .kernel_symbolizer
            .symbolize(&Source::Kernel(Kernel::default()), Input::AbsAddr(addr))?;
        Ok(rst)
    }

    fn init_symbolizer(&mut self, tgid: u32) -> Result<()> {
        let (exe, mtime) = exe_name_and_change_time(tgid)?;
        if let Some(symboliser) = self.executable_symbolizers.get(&(exe.clone(), mtime)) {
            self.process_symbolizers.insert(tgid, symboliser.clone());
            return Ok(());
        } else {
            let symbolizer = symbolize::Symbolizer::builder()
                .enable_code_info(false)
                .enable_inlined_fns(false)
                .enable_auto_reload(false)
                .build();
            let symboliser = Rc::new(ExecutableSymbolizer {
                symbolizer,
                exe: exe.clone(),
                mtime,
            });
            debug!("symbolizer for tgid={} with executable {} initialized", tgid, exe);
            self.executable_symbolizers.insert((exe, mtime), symboliser.clone());
            self.process_symbolizers.insert(tgid, symboliser);
        }
        let symbolizer = self.process_symbolizers.get(&tgid).unwrap();
        if let Err(err) = symbolizer.symbolizer.symbolize(
            &Source::Process(Process {
                pid: blazesym::Pid::Pid(NonZeroU32::new(tgid).unwrap()),
                debug_syms: false,
                perf_map: false,
                map_files: true,
                _non_exhaustive: (),
            }),
            Input::AbsAddr(&[]),
        ) {
            debug!("caching unsuccesful for tgid={} err={}", tgid, err);
        }
        Ok(())
    }

    fn drop_symbolizer(&mut self, tgid: u32) -> Result<()> {
        if let Some(symbolizer) = self.process_symbolizers.remove(&tgid) {
            debug!(
                "dropping symbolized reference for tgid={}, counter {}",
                tgid,
                Rc::strong_count(&symbolizer)
            );
            // last one was removed from process_symbolizers and one left in executable_symbolizers
            if Rc::strong_count(&symbolizer) <= 2 {
                debug!("symbolizer for exe={} dropped", symbolizer.exe);
                self.executable_symbolizers
                    .remove(&(symbolizer.exe.clone(), symbolizer.mtime));
            }
        }
        Ok(())
    }

    fn symbolize_process(&self, tgid: u32, addr: &[u64]) -> Result<Vec<Symbolized>> {
        let symbolizer = match self.process_symbolizers.get(&tgid) {
            Some(symbolizer) => &symbolizer.symbolizer,
            None => {
                // if process exits at the same time when batch is written we may lose several
                // events that are emitted after receiving close event.
                anyhow::bail!("missing symbolizer for tgid={}", tgid);
            }
        };
        let rst = symbolizer.symbolize(
            &Source::Process(Process {
                pid: blazesym::Pid::Pid(NonZeroU32::new(tgid).unwrap()),
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

fn exe_name_and_change_time(tgid: u32) -> Result<(String, u64)> {
    let path = format!("/proc/{}/exe", tgid);
    let exe = fs::read_link(path)?;
    let meta = exe.metadata()?;
    let mtime = meta.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    Ok((exe.to_string_lossy().to_string(), mtime))
}
