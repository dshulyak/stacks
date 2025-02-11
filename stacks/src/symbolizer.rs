use std::{
    collections::{HashMap, HashSet},
    iter::empty,
    path::PathBuf,
    rc::Rc,
};

use anyhow::Result;
use blazesym::{
    symbolize::{self, Input, Kernel, Process, Source, Symbolized},
    Pid,
};
use bytes::Bytes;
use tracing::{debug, instrument, warn};

use crate::parquet::{Group, ResolvedStack};

pub(crate) trait Frames {
    fn frames(&self, id: i32) -> Result<Vec<u64>>;
}

#[instrument(skip_all)]
pub(crate) fn symbolize(symbolizer: &BlazesymSymbolizer, stacks: &impl Frames, stack_group: &mut Group) {
    let mut resolved_addresses: HashMap<(i32, u64), ResolvedStack> = HashMap::new();
    let kstacks: HashSet<_> = stack_group.raw_kstacks().collect();
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
    for (tgid, ustack) in stack_group.raw_ustacks() {
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
        let process_symbolizer = match symbolizer.symbolize_userspace(tgid as u32) {
            Ok(sym) => sym,
            Err(err) => {
                debug!("get userspace symbolizer {}: {}", tgid, err);
                continue;
            }
        };
        let symbols = match process_symbolizer.symbolize(&req) {
            Ok(syms) => syms,
            Err(err) => {
                debug!("get symbols {}: {}", tgid, err);
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

    let original_kstacks = stack_group.raw_kstacks().collect::<Vec<_>>();
    let original_ustacks = stack_group.raw_ustacks().collect::<Vec<_>>();

    let zipped = original_kstacks.into_iter().zip(original_ustacks);
    for (kstack_id, (tgid, ustack_id)) in zipped {
        match (
            to_symbols(&ustack_traces, &resolved_addresses, tgid, ustack_id),
            to_symbols(&traces, &resolved_addresses, -1, kstack_id),
        ) {
            (Some(ustacks), Some(kstacks)) => {
                stack_group.update_stacks_with_symbolized(ustacks, kstacks);
            }
            (Some(ustacks), None) => {
                stack_group.update_stacks_with_symbolized(ustacks, empty());
            }
            (None, Some(kstacks)) => {
                stack_group.update_stacks_with_symbolized(empty(), kstacks);
            }
            (None, None) => {
                stack_group.update_stacks_with_symbolized(empty(), empty());
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

#[derive(Debug)]
pub(crate) struct ExecutableSymbolizer {
    symbolizer: symbolize::Symbolizer,
    source: Process,
    exe: PathBuf,
    mtime: u64,
}

impl ExecutableSymbolizer {
    pub(crate) fn symbolize(&self, addr: &[u64]) -> Result<Vec<Symbolized<'_>>> {
        let rst = self
            .symbolizer
            .symbolize(&Source::Process(self.source.clone()), Input::AbsAddr(addr))?;
        Ok(rst)
    }
}

pub(crate) struct BlazesymSymbolizer {
    // kernel_symbolizer can be reused for the whole lifetime of the program,
    // technically it is exactly same object as any other symbolizer, but it will not cache any userspace files for
    // symbolizations
    kernel_symbolizer: symbolize::Symbolizer,
    // symbolizers for userspace data have to live until last batch of frames from the process is symbolized
    // symbolization is delayed as it is more efficient to batch request for the same symbols
    // hence we cannot drop symbolizer immediately once process exits
    executable_symbolizers: HashMap<(PathBuf, u64), Rc<ExecutableSymbolizer>>,
    process_symbolizers: HashMap<u32, Rc<ExecutableSymbolizer>>,
}

impl BlazesymSymbolizer {
    pub(crate) fn new() -> Self {
        Self {
            kernel_symbolizer: symbolize::Symbolizer::new(),
            executable_symbolizers: HashMap::new(),
            process_symbolizers: HashMap::new(),
        }
    }

    pub(crate) fn symbolize_kernel(&self, addr: &[u64]) -> Result<Vec<Symbolized>> {
        let rst = self
            .kernel_symbolizer
            .symbolize(&Source::Kernel(Kernel::default()), Input::AbsAddr(addr))?;
        Ok(rst)
    }

    pub(crate) fn init_symbolizer(&mut self, tgid: u32, exe: PathBuf, mtime: u64, buildid: Bytes) -> Result<Bytes> {
        if let Some(symboliser) = self.executable_symbolizers.get(&(exe.clone(), mtime)) {
            self.process_symbolizers.insert(tgid, symboliser.clone());
        } else {
            let symbolizer = symbolize::Symbolizer::builder()
                .enable_code_info(true)
                .enable_inlined_fns(true)
                .enable_auto_reload(false)
                .build();
            let symboliser = Rc::new(ExecutableSymbolizer {
                symbolizer,
                source: Process {
                    pid: Pid::Pid(tgid.try_into()?),
                    debug_syms: true,
                    perf_map: false,
                    map_files: false,
                    _non_exhaustive: (),
                },
                exe: exe.clone(),
                mtime,
            });
            debug!(executable = ?exe, tgid, "symbolizer initialized");
            self.executable_symbolizers.insert((exe, mtime), symboliser.clone());
            self.process_symbolizers.insert(tgid, symboliser);
        }
        if let Some(symbolizer) = self.process_symbolizers.get(&tgid) {
            if let Err(err) = symbolizer
                .symbolizer
                .symbolize(&Source::Process(symbolizer.source.clone()), Input::AbsAddr(&[]))
            {
                debug!("caching unsuccesful for tgid={} err={}", tgid, err);
            }
        }

        Ok(buildid)
    }

    pub(crate) fn drop_symbolizer(&mut self, tgid: u32) -> Result<()> {
        if let Some(symbolizer) = self.process_symbolizers.remove(&tgid) {
            debug!(
                "dropping symbolized reference for tgid={}, counter {}",
                tgid,
                Rc::strong_count(&symbolizer)
            );
            // last one was removed from process_symbolizers and one left in executable_symbolizers
            if Rc::strong_count(&symbolizer) <= 2 {
                debug!("symbolizer for exe={:?} dropped", symbolizer.exe);
                self.executable_symbolizers
                    .remove(&(symbolizer.exe.clone(), symbolizer.mtime));
            }
        }
        Ok(())
    }

    pub(crate) fn symbolize_userspace(&self, tgid: u32) -> Result<Rc<ExecutableSymbolizer>> {
        let symbolizer = match self.process_symbolizers.get(&tgid) {
            Some(symbolizer) => symbolizer.clone(),
            None => {
                // if process exits at the same time when batch is written we may lose several
                // events that are emitted after receiving close event.
                anyhow::bail!("missing symbolizer for tgid={}", tgid);
            }
        };
        Ok(symbolizer)
    }
}
