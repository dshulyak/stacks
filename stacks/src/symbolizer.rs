use std::{
    collections::{HashMap, HashSet},
    fs,
    iter::empty,
    num::NonZeroU32,
    path::PathBuf,
    rc::Rc,
    time::SystemTime,
};

use anyhow::{Context, Result};
use blazesym::{
    helper::read_elf_build_id,
    symbolize::{self, Input, Kernel, Process, Source, Symbolized},
};
use bytes::Bytes;
use tracing::{debug, instrument, warn};

use crate::parquet::{Group, ResolvedStack};

pub(crate) trait Frames {
    fn frames(&self, id: i32) -> Result<Vec<u64>>;
}

#[instrument(skip_all)]
pub(crate) fn symbolize(symbolizer: &impl Symbolizer, stacks: &impl Frames, stack_group: &mut Group) {
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

pub(crate) trait Symbolizer {
    fn new() -> Self;

    fn symbolize_kernel(&self, addr: &[u64]) -> Result<Vec<Symbolized>>;

    fn init_symbolizer(&mut self, tgid: u32) -> Result<Bytes>;

    fn drop_symbolizer(&mut self, tgid: u32) -> Result<()>;

    fn symbolize_process(&self, tgid: u32, addr: &[u64]) -> Result<Vec<Symbolized>>;
}

#[derive(Debug)]
struct ExecutableSymbolizer {
    symbolizer: symbolize::Symbolizer,
    exe: PathBuf,
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
    executable_symbolizers: HashMap<(PathBuf, u64), Rc<ExecutableSymbolizer>>,
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

    fn init_symbolizer(&mut self, tgid: u32) -> Result<Bytes> {
        let (exe, mtime) =
            exe_name_and_change_time(tgid).with_context(|| format!("reading exe name and mtime for tgid={}", tgid))?;
        let buildid = read_elf_build_id(&exe)
            .context("read buildid")?
            .map(|buildid| Bytes::copy_from_slice(buildid.as_ref()))
            .unwrap_or_default();

        if let Some(symboliser) = self.executable_symbolizers.get(&(exe.clone(), mtime)) {
            self.process_symbolizers.insert(tgid, symboliser.clone());
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
            debug!("symbolizer for tgid={} with executable {:?} initialized", tgid, exe);
            self.executable_symbolizers.insert((exe, mtime), symboliser.clone());
            self.process_symbolizers.insert(tgid, symboliser);
        }
        let symbolizer = self.process_symbolizers.get(&tgid).unwrap();
        if let Err(err) = symbolizer.symbolizer.symbolize(
            &Source::Process(Process {
                pid: blazesym::Pid::Pid(NonZeroU32::new(tgid).unwrap()),
                debug_syms: true,
                perf_map: false,
                map_files: false,
                _non_exhaustive: (),
            }),
            Input::AbsAddr(&[]),
        ) {
            debug!("caching unsuccesful for tgid={} err={}", tgid, err);
        }
        Ok(buildid)
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
                debug!("symbolizer for exe={:?} dropped", symbolizer.exe);
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
                map_files: false,
                _non_exhaustive: (),
            }),
            Input::AbsAddr(addr),
        )?;
        Ok(rst)
    }
}

fn exe_name_and_change_time(tgid: u32) -> Result<(PathBuf, u64)> {
    let path = format!("/proc/{}/exe", tgid);
    let exe = fs::read_link(path)?;
    let meta = exe.metadata()?;
    let mtime = meta.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    Ok((exe, mtime))
}
