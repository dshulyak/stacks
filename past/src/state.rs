use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use plain::Plain;
use tracing::{debug, info, warn};

use crate::{
    parquet::{Compression, Event, EventKind, Group, GroupWriter},
    past_types,
    symbolizer::{symbolize, Frames, Symbolizer},
};

#[derive(Debug)]
pub(crate) struct Config {
    pub directory: PathBuf,
    pub timestamp_adjustment: u64,
    pub groups_per_file: usize,
    pub rows_per_group: usize,
    pub perf_event_frequency: i64,
    pub compression: Compression,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

#[derive(Debug)]
pub(crate) struct Stats {
    pub rows_in_current_file: usize,
    pub total_rows: usize,
    pub current_file_index: usize,
    pub missing_stacks_counter: HashMap<i32, usize>,
}

#[derive(Debug)]
pub(crate) struct ProcessInfo {
    pub(crate) command: Bytes,
    pub(crate) buildid: Bytes,
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

pub(crate) struct State<Fr: Frames, Sym: Symbolizer> {
    cfg: Config,
    writer: Option<GroupWriter<File>>,
    frames: Fr,
    symbolizer: Sym,
    // cleanup should occur after frames from last batch were collected
    symbolizer_tgid_cleanup: HashSet<u32>,
    tgid_process_info: HashMap<u32, ProcessInfo>,
    tgid_span_id_pid_to_enter: BTreeMap<(u32, u64, u32), SpanEnter>,
    group: Group,
    page_size: u64,
    stats: Stats,
}

// parquet file is invalid until footer is written.
// writing to a file with different prefix allows to register only valid files without stopping the program.
// also if program crashes it is much more desirable to avoid manual recovery by deleting unfinished file.
const PENDING_FILE_PREFIX: &str = "PENDING";
const FILE_PREFIX: &str = "STACKS";

impl<Fr: Frames, Sym: Symbolizer> State<Fr, Sym> {
    pub(crate) fn new(cfg: Config, frames: Fr, symbolizer: Sym) -> Result<Self> {
        let stats = Stats {
            rows_in_current_file: 0,
            total_rows: 0,
            current_file_index: 0,
            missing_stacks_counter: HashMap::new(),
        };
        let f = create_file(&cfg.directory, PENDING_FILE_PREFIX).context("creating pending file")?;
        let writer = GroupWriter::with_compression(f, cfg.compression)?;
        let group = Group::new(cfg.rows_per_group);
        let page_size = page_size()?;
        Ok(State {
            cfg,
            writer: Some(writer),
            frames,
            symbolizer,
            symbolizer_tgid_cleanup: HashSet::new(),
            tgid_process_info: HashMap::new(),
            tgid_span_id_pid_to_enter: BTreeMap::new(),
            group,
            page_size,
            stats,
        })
    }

    pub(crate) fn drop_known_state(&mut self) -> Result<()> {
        for tgid in self.tgid_process_info.keys() {
            self.symbolizer.drop_symbolizer(*tgid)?;
        }
        self.tgid_process_info.clear();
        self.tgid_span_id_pid_to_enter.clear();
        self.symbolizer_tgid_cleanup.clear();
        Ok(())
    }

    fn save_event(&mut self, event: Received) -> Result<()> {
        // all integers are cast to signed because of the API provided by rust parquet lib
        // arithmetic operations will be correctly performed on unsigned integers, configured in schema
        // TODO maybe i should move cast closer to the schema definition
        match event {
            Received::Switch(event) => {
                let process_info = match self.tgid_process_info.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", event.tgid);
                    }
                };
                self.group.save_event(Event {
                    ts: (event.end + self.cfg.timestamp_adjustment) as i64,
                    kind: EventKind::Switch,
                    duration: (event.end - event.start) as i64,
                    cpu: event.cpu_id as i32,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    ustack: event.ustack,
                    kstack: event.kstack,
                    ..Default::default()
                });
            }
            Received::Profile(event) => {
                if event.ustack > 0 || event.kstack > 0 {
                    let process_info = match self.tgid_process_info.get(&event.tgid) {
                        Some(command) => command,
                        None => {
                            anyhow::bail!("missing command for pid {}", event.tgid);
                        }
                    };
                    self.group.save_event(Event {
                        ts: (event.timestamp + self.cfg.timestamp_adjustment) as i64,
                        duration: self.cfg.perf_event_frequency,
                        kind: EventKind::Profile,
                        cpu: event.cpu_id as i32,
                        tgid: event.tgid as i32,
                        pid: event.pid as i32,
                        command: process_info.command.clone(),
                        buildid: process_info.buildid.clone(),
                        ustack: event.ustack,
                        kstack: event.kstack,
                        ..Default::default()
                    });
                };
            }
            Received::Rss(event) => {
                let process_info = match self.tgid_process_info.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", event.tgid);
                    }
                };
                self.group.save_event(Event {
                    ts: (event.ts + self.cfg.timestamp_adjustment) as i64,
                    kind: EventKind::Rss,
                    tgid: event.tgid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    amount: (event.rss * self.page_size) as i64,
                    ustack: event.ustack,
                    kstack: event.kstack,
                    ..Default::default()
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
                let process_info = match self.tgid_process_info.get(&event.tgid) {
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
                self.group.save_event(Event {
                    ts: (event.ts + self.cfg.timestamp_adjustment) as i64,
                    duration: (event.ts - span.last_enter_ts) as i64,
                    kind: EventKind::TraceExit,
                    cpu: event.cpu_id as i32,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    span_id: event.span_id as i64,
                    parent_id: span.parent_id as i64,
                    id: span.id as i64,
                    amount: span.amount as i64,
                    trace_name: span.name.clone(),
                    ustack: event.ustack,
                    ..Default::default()
                });
            }
            Received::TraceClose(event) => {
                // record it only once for any pid where this span_id has entered before
                let pids = self
                    .tgid_span_id_pid_to_enter
                    .range((event.tgid, event.span_id, 0)..(event.tgid, event.span_id, u32::MAX))
                    .map(|(k, _)| k.2)
                    .collect::<Vec<_>>();
                let process_info = self.tgid_process_info.get(&pids[0]);
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
                    if let Some(process_info) = process_info {
                        self.group.save_event(Event {
                            ts: (event.ts + self.cfg.timestamp_adjustment) as i64,
                            duration: (event.ts - span.first_enter_ts) as i64,
                            kind: EventKind::TraceClose,
                            cpu: event.cpu_id as i32,
                            tgid: event.tgid as i32,
                            pid: pid as i32,
                            command: process_info.command.clone(),
                            buildid: process_info.buildid.clone(),
                            span_id: event.span_id as i64,
                            parent_id: span.parent_id as i64,
                            id: span.id as i64,
                            amount: span.amount as i64,
                            trace_name: span.name.clone(),
                            ..Default::default()
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

    pub(crate) fn on_event(&mut self, event: Received) -> Result<()> {
        // TODO i need to adjust stats based on response from on_event
        // this is hotfix for ci
        match event {
            Received::ProcessExec(event) => {
                let buildid = match self.symbolizer.init_symbolizer(event.tgid) {
                    Ok(builid) => builid,
                    Err(err) => {
                        warn!("failed to init symbolizer for tgid {}: {:?}", event.tgid, err);
                        Bytes::default()
                    }
                };
                let comm = null_terminated(&event.comm);
                match self.tgid_process_info.entry(event.tgid) {
                    hash_map::Entry::Vacant(vacant) => {
                        vacant.insert(ProcessInfo {
                            command: Bytes::copy_from_slice(comm),
                            buildid,
                        });
                    }
                    hash_map::Entry::Occupied(mut occupied) => {
                        if occupied.get().command != comm {
                            occupied.insert(ProcessInfo {
                                command: Bytes::copy_from_slice(comm),
                                buildid,
                            });
                        }
                    }
                };
            }
            Received::ProcessExit(event) => {
                self.symbolizer_tgid_cleanup.insert(event.tgid);
            }
            Received::TraceEnter(_) | Received::Unknown(_) => {}
            Received::Profile(event) => {
                // -1 is set if stack is not collected
                if event.ustack < -1 {
                    self.stats
                        .missing_stacks_counter
                        .entry(event.ustack)
                        .and_modify(|e| *e += 1)
                        .or_insert(1);
                }
                self.stats.total_rows += 1;
                self.stats.rows_in_current_file += 1;
            }
            Received::Switch(_) | Received::Rss(_) | Received::TraceExit(_) | Received::TraceClose(_) => {
                self.stats.total_rows += 1;
                self.stats.rows_in_current_file += 1;
            }
        }

        if let Err(err) = self.save_event(event) {
            warn!("failed to collect event: {:?}", err);
        }
        if self.group.is_full() {
            debug!("group is full, symbolizing and flushing");
            symbolize(&self.symbolizer, &self.frames, &mut self.group);
            self.writer
                .as_mut()
                .expect("writer must exist")
                .write(self.group.for_writing())?;
            for tgid in self.symbolizer_tgid_cleanup.drain() {
                self.symbolizer.drop_symbolizer(tgid)?;
            }
        }

        if self.stats.rows_in_current_file == self.cfg.rows_per_group * self.cfg.groups_per_file {
            self.exit_current_file()?;
            self.writer = Some(GroupWriter::with_compression(
                create_file(&self.cfg.directory, PENDING_FILE_PREFIX).context("creating pending file")?,
                self.cfg.compression,
            )?);
            self.stats.current_file_index += 1;
            self.stats.rows_in_current_file = 0;
        }
        Ok(())
    }

    pub(crate) fn exit_current_file(&mut self) -> Result<()> {
        if !self.stats.missing_stacks_counter.is_empty() {
            info!("missing stacks due to errors: {:?}", self.stats.missing_stacks_counter);
            self.stats.missing_stacks_counter.clear();
        }
        if let Some(writer) = self.writer.take() {
            on_exit(writer, &mut self.group, &self.symbolizer, &self.frames).context("closing last file")?;
            move_file_with_timestamp(
                &self.cfg.directory,
                PENDING_FILE_PREFIX,
                FILE_PREFIX,
                self.stats.current_file_index,
            )?;
        }
        Ok(())
    }
}

fn on_exit<W: Write + Send>(
    mut stack_writer: GroupWriter<W>,
    stack_group: &mut Group,
    symbolizer: &impl Symbolizer,
    stacks: &impl Frames,
) -> Result<()> {
    if !stack_group.is_empty() {
        debug!("symbolizing remaining stacks and flushing group");
        symbolize(symbolizer, stacks, stack_group);
        stack_writer.write(stack_group.for_writing())?;
    }
    stack_writer.close()?;
    Ok(())
}

fn page_size() -> Result<u64> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => anyhow::bail!("sysconf _SC_PAGESIZE failed"),
        x => Ok(x as u64),
    }
}

fn create_file(dir: &Path, prefix: &str) -> Result<File> {
    Ok(File::create(dir.join(format!("{}.parquet", prefix)))?)
}

fn move_file_with_timestamp(dir: &Path, from_prefix: &str, to_prefix: &str, index: usize) -> Result<()> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    let from = dir.join(format!("{}.parquet", from_prefix));
    let to = dir.join(format!("{}-{}-{}.parquet", to_prefix, index, now));
    fs::rename(from, to)?;
    Ok(())
}

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
    Profile(&'a past_types::perf_cpu_event),
    ProcessExec(&'a past_types::process_exec_event),
    ProcessExit(&'a past_types::process_exit_event),
    TraceEnter(&'a past_types::tracing_enter_event),
    TraceExit(&'a past_types::tracing_exit_event),
    TraceClose(&'a past_types::tracing_close_event),
    Rss(&'a past_types::rss_stat_event),
    Unknown(&'a [u8]),
}

impl<'a> From<&'a [u8]> for Received<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        match bytes[0] {
            0 => Received::Switch(to_event(bytes)),
            1 => Received::Profile(to_event(bytes)),
            2 => Received::TraceEnter(to_event(bytes)),
            3 => Received::TraceExit(to_event(bytes)),
            4 => Received::TraceClose(to_event(bytes)),
            5 => Received::ProcessExit(to_event(bytes)),
            6 => Received::ProcessExec(to_event(bytes)),
            7 => Received::Rss(to_event(bytes)),
            _ => Received::Unknown(bytes),
        }
    }
}

pub(crate) fn null_terminated(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}
