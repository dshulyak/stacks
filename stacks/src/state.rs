use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    fs,
    path::PathBuf,
    time::SystemTime,
};

use anyhow::{Context, Result};
use blazesym::helper::read_elf_build_id;
use bytes::Bytes;
use crossbeam::channel::Sender;
use plain::Plain;
use tracing::{debug, warn};

use crate::{
    bpf::ProgramName,
    parquet::{Event, EventKind, Group},
    stacks_types::{self, blk_io_event, net_io_event, vfs_io_event},
    state_writer::WriterRequest,
};

#[derive(Debug)]
pub(crate) struct Stats {
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
    span_id: u64,
    id: u64,
    amount: u64,
    name: Bytes,
    first_enter_ts: u64,
    last_enter_ts: u64,
}

pub(crate) struct State {
    timestamp_adjustment: u64,
    rows_per_group: usize,
    perf_event_frequency: i64,
    state_writer_sender: Sender<WriterRequest>,
    tgid_process_info: HashMap<u32, ProcessInfo>,
    tgid_span_id_pid_to_enter: BTreeMap<(u32, u64, u32), SpanEnter>,
    // opened_spans contain pid -> span_id
    // added on trace_enter, remove on trace_exit
    opened_spans: HashMap<u32, Vec<u64>>,
    group: Box<Group>,
    page_size: u64,
    stats: Stats,
}

impl State {
    pub(crate) fn new(
        timestamp_adjustment: u64,
        rows_per_group: usize,
        perf_event_frequency: i64,
        state_writer_sender: Sender<WriterRequest>,
    ) -> Result<Self> {
        let stats = Stats {
            missing_stacks_counter: HashMap::new(),
        };
        let group = Box::new(Group::new(rows_per_group));
        let page_size = page_size()?;
        Ok(State {
            timestamp_adjustment,
            rows_per_group,
            perf_event_frequency,
            state_writer_sender,
            tgid_process_info: HashMap::new(),
            tgid_span_id_pid_to_enter: BTreeMap::new(),
            opened_spans: HashMap::new(),
            group,
            page_size,
            stats,
        })
    }

    pub(crate) fn drop_known_state(&mut self) -> Result<()> {
        self.state_writer_sender.send(WriterRequest::Reset)?;
        self.tgid_process_info.clear();
        self.tgid_span_id_pid_to_enter.clear();
        self.opened_spans.clear();
        Ok(())
    }

    fn save_event(&mut self, received: Received) -> Result<()> {
        // all integers are cast to signed because of the API provided by rust parquet lib
        // arithmetic operations will be correctly performed on unsigned integers, configured in schema
        // TODO maybe i should move cast closer to the schema definition
        match received {
            Received::Switch(event) => {
                let process_info = match self.tgid_process_info.get(&event.tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", event.tgid);
                    }
                };
                // it means that the span was opened, while the process was context-switched.
                // such information might be useful to identify issues with async tasks.
                let span = self.get_last_open_span(event.tgid, event.pid);
                self.group.save_event(Event {
                    ts: (event.end + self.timestamp_adjustment) as i64,
                    kind: received.try_into()?,
                    duration: (event.end - event.start) as i64,
                    cpu: event.cpu_id as i32,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    ustack: event.ustack,
                    kstack: event.kstack,
                    span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                    parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                    trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
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
                    let span = self.get_last_open_span(event.tgid, event.pid);
                    self.group.save_event(Event {
                        ts: (event.timestamp + self.timestamp_adjustment) as i64,
                        duration: self.perf_event_frequency,
                        kind: EventKind::Profile,
                        cpu: event.cpu_id as i32,
                        tgid: event.tgid as i32,
                        pid: event.pid as i32,
                        command: process_info.command.clone(),
                        buildid: process_info.buildid.clone(),
                        ustack: event.ustack,
                        kstack: event.kstack,
                        span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                        parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                        trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
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
                let span = self.get_last_open_span(event.tgid, event.pid);
                self.group.save_event(Event {
                    ts: (event.ts + self.timestamp_adjustment) as i64,
                    kind: received.try_into()?,
                    tgid: event.tgid as i32,
                    pid: event.pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    amount: (event.rss * self.page_size) as i64,
                    ustack: event.ustack,
                    kstack: event.kstack,
                    span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                    parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                    trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
                    ..Default::default()
                });
            }
            Received::TraceEnter(event) => {
                self.opened_spans.entry(event.pid).or_default().push(event.span_id);
                let entry = self
                    .tgid_span_id_pid_to_enter
                    .entry((event.tgid, event.span_id, event.pid));
                match entry {
                    btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(SpanEnter {
                            parent_id: event.parent_id,
                            span_id: event.span_id,
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
                let spans = self.opened_spans.get_mut(&event.pid);
                match spans {
                    Some(spans) => {
                        if let Some(last) = spans.pop() {
                            if last != event.span_id {
                                warn!("span_id mismatch for pid {}", event.pid);
                                spans.clear();
                            }
                        }
                    }
                    None => {
                        warn!("missing span for pid {}", event.pid);
                    }
                }
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
                    ts: (event.ts + self.timestamp_adjustment) as i64,
                    duration: (event.ts - span.last_enter_ts) as i64,
                    kind: received.try_into()?,
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
                    kstack: event.kstack,
                });
            }
            Received::TraceClose(event) => {
                // record close event only once for any pid where this span_id has entered before
                let pids = self
                    .tgid_span_id_pid_to_enter
                    .range((event.tgid, event.span_id, 0)..(event.tgid, event.span_id, u32::MAX))
                    .map(|(k, _)| k.2)
                    .collect::<Vec<_>>();
                let process_info = self.tgid_process_info.get(&event.tgid);
                for (i, pid) in pids.into_iter().enumerate() {
                    // delete all observed
                    let span = match self.tgid_span_id_pid_to_enter.remove(&(event.tgid, event.span_id, pid)) {
                        Some(span) => span,
                        None => {
                            anyhow::bail!("missing span for pid {} span_id {}", pid, event.span_id);
                        }
                    };
                    // record only first
                    if i > 0 {
                        continue;
                    }
                    if let Some(process_info) = process_info {
                        self.group.save_event(Event {
                            ts: (event.ts + self.timestamp_adjustment) as i64,
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
            Received::Block(event) => {
                // TODO rw needs to be refactored away, it is nicer to define
                // separate type for event
                let blk_io_event {
                    r#type: _,
                    rw: _,
                    tgid,
                    pid,
                    start,
                    end,
                    size,
                    ustack,
                    kstack,
                    __pad_12,
                } = event;
                let process_info = match self.tgid_process_info.get(tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", tgid);
                    }
                };
                let span = self.get_last_open_span(*tgid, *pid);
                self.group.save_event(Event {
                    ts: (end + self.timestamp_adjustment) as i64,
                    duration: (end - start) as i64,
                    kind: received.try_into()?,
                    tgid: *tgid as i32,
                    pid: *pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    amount: *size as i64,
                    ustack: *ustack,
                    kstack: *kstack,
                    span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                    parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                    trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
                    id: span.map(|s| s.id as i64).unwrap_or_default(),
                    ..Default::default()
                });
            }
            Received::Vfs(event) => {
                let vfs_io_event {
                    r#type: _,
                    rw: _,
                    tgid,
                    pid,
                    ts,
                    size,
                    ustack,
                    kstack,
                    __pad_12,
                } = event;
                let process_info = match self.tgid_process_info.get(tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", tgid);
                    }
                };
                let span = self.get_last_open_span(*tgid, *pid);
                self.group.save_event(Event {
                    ts: (*ts + self.timestamp_adjustment) as i64,
                    kind: received.try_into()?,
                    tgid: *tgid as i32,
                    pid: *pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    amount: *size as i64,
                    ustack: *ustack,
                    kstack: *kstack,
                    span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                    parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                    trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
                    id: span.map(|s| s.id as i64).unwrap_or_default(),
                    ..Default::default()
                });
            }
            Received::UdpRecv(event)
            | Received::UdpSend(event)
            | Received::TcpRecv(event)
            | Received::TcpSend(event) => {
                let net_io_event {
                    r#type: _,
                    tgid,
                    pid,
                    ts,
                    size,
                    ustack,
                    kstack,
                    __pad_12,
                } = event;
                let process_info = match self.tgid_process_info.get(tgid) {
                    Some(command) => command,
                    None => {
                        anyhow::bail!("missing command for pid {}", tgid);
                    }
                };
                let span = self.get_last_open_span(*tgid, *pid);
                self.group.save_event(Event {
                    ts: (*ts + self.timestamp_adjustment) as i64,
                    kind: received.try_into()?,
                    tgid: *tgid as i32,
                    pid: *pid as i32,
                    command: process_info.command.clone(),
                    buildid: process_info.buildid.clone(),
                    amount: *size as i64,
                    ustack: *ustack,
                    kstack: *kstack,
                    span_id: span.map(|s| s.span_id as i64).unwrap_or_default(),
                    parent_id: span.map(|s| s.parent_id as i64).unwrap_or_default(),
                    trace_name: span.map(|s| s.name.clone()).unwrap_or_default(),
                    id: span.map(|s| s.id as i64).unwrap_or_default(),
                    ..Default::default()
                });
            }
        }
        Ok(())
    }

    pub(crate) fn on_event(&mut self, event: Received) -> Result<()> {
        match event {
            Received::ProcessExec(event) => {
                let (exe, mtime, buildid) = exe_change_time_build_id(event.tgid)?;
                debug!(executable = ?exe, tgid = event.tgid, "process started");
                self.state_writer_sender.send(WriterRequest::ProcessCreated(
                    event.tgid,
                    exe,
                    mtime,
                    buildid.clone(),
                ))?;
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
                self.state_writer_sender
                    .send(WriterRequest::ProcessExited(event.tgid))?;
            }
            Received::TraceEnter(_) => {}
            Received::Profile(event) => {
                // -1 is set if stack is not collected
                if event.ustack < -1 {
                    self.stats
                        .missing_stacks_counter
                        .entry(event.ustack)
                        .and_modify(|e| *e += 1)
                        .or_insert(1);
                }
            }
            Received::UdpRecv(_)
            | Received::UdpSend(_)
            | Received::TcpRecv(_)
            | Received::TcpSend(_)
            | Received::Vfs(_)
            | Received::Block(_)
            | Received::Switch(_)
            | Received::Rss(_)
            | Received::TraceExit(_)
            | Received::TraceClose(_) => {}
        }

        if let Err(err) = self.save_event(event) {
            warn!("failed to collect event: {:?}", err);
        }
        if self.group.is_full() {
            debug!("group is full, symbolizing and flushing");
            let old = std::mem::replace(&mut self.group, Box::new(Group::new(self.rows_per_group)));
            let request = WriterRequest::GroupFull(old);
            self.state_writer_sender
                .send(request)
                .context("write request should never fail")?;
        }
        Ok(())
    }

    pub(crate) fn on_exit(&mut self) {
        if self.group.is_empty() {
            return;
        }
        let old = std::mem::replace(&mut self.group, Box::new(Group::new(self.rows_per_group)));
        let request = WriterRequest::GroupFull(old);
        self.state_writer_sender
            .send(request)
            .context("write request should never fail")
            .unwrap();
    }

    fn get_last_open_span(&self, tgid: u32, pid: u32) -> Option<&SpanEnter> {
        self.opened_spans
            .get(&pid)
            .and_then(|spans| spans.last())
            .and_then(|span_id| self.tgid_span_id_pid_to_enter.get(&(tgid, *span_id, pid)))
    }
}

fn page_size() -> Result<u64> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => anyhow::bail!("sysconf _SC_PAGESIZE failed"),
        x => Ok(x as u64),
    }
}

unsafe impl Plain for stacks_types::switch_event {}
unsafe impl Plain for stacks_types::perf_cpu_event {}
unsafe impl Plain for stacks_types::tracing_enter_event {}
unsafe impl Plain for stacks_types::tracing_exit_event {}
unsafe impl Plain for stacks_types::tracing_close_event {}
unsafe impl Plain for stacks_types::process_exit_event {}
unsafe impl Plain for stacks_types::process_exec_event {}
unsafe impl Plain for stacks_types::rss_stat_event {}
unsafe impl Plain for stacks_types::blk_io_event {}
unsafe impl Plain for stacks_types::vfs_io_event {}
unsafe impl Plain for stacks_types::net_io_event {}

fn to_event<T: Plain>(bytes: &[u8]) -> &T {
    plain::from_bytes(bytes).expect("failed to convert bytes to event")
}

#[derive(Debug, Clone)]
pub(crate) enum Received<'a> {
    Switch(&'a stacks_types::switch_event),
    Profile(&'a stacks_types::perf_cpu_event),
    ProcessExec(&'a stacks_types::process_exec_event),
    ProcessExit(&'a stacks_types::process_exit_event),
    TraceEnter(&'a stacks_types::tracing_enter_event),
    TraceExit(&'a stacks_types::tracing_exit_event),
    TraceClose(&'a stacks_types::tracing_close_event),
    Rss(&'a stacks_types::rss_stat_event),
    Block(&'a stacks_types::blk_io_event),
    Vfs(&'a stacks_types::vfs_io_event),
    UdpRecv(&'a stacks_types::net_io_event),
    UdpSend(&'a stacks_types::net_io_event),
    TcpRecv(&'a stacks_types::net_io_event),
    TcpSend(&'a stacks_types::net_io_event),
}

impl Received<'_> {
    pub(crate) fn program_name(&self) -> ProgramName {
        // TODO i need to have only one enum
        match self {
            Received::Switch(_) => ProgramName::Switch,
            Received::Profile(_) => ProgramName::Profile,
            Received::ProcessExec(_) => ProgramName::Exec,
            Received::ProcessExit(_) => ProgramName::Exit,
            Received::TraceEnter(_) => ProgramName::TraceEnter,
            Received::TraceExit(_) => ProgramName::TraceExit,
            Received::TraceClose(_) => ProgramName::TraceClose,
            Received::Rss(_) => ProgramName::Rss,
            Received::Block(_) => ProgramName::Block,
            Received::Vfs(_) => ProgramName::Vfs,
            Received::UdpRecv(_) => ProgramName::Net,
            Received::UdpSend(_) => ProgramName::Net,
            Received::TcpRecv(_) => ProgramName::Net,
            Received::TcpSend(_) => ProgramName::Net,
        }
    }
}

impl<'a> TryFrom<Received<'a>> for EventKind {
    type Error = anyhow::Error;

    fn try_from(event: Received<'a>) -> Result<Self> {
        match event {
            Received::Switch(_) => Ok(EventKind::Switch),
            Received::Profile(_) => Ok(EventKind::Profile),
            Received::ProcessExec(_) => anyhow::bail!("exec event is not recorded"),
            Received::ProcessExit(_) => anyhow::bail!("exit event is not recorded"),
            Received::TraceEnter(_) => anyhow::bail!("trace enter event is not recorded"),
            Received::TraceExit(_) => Ok(EventKind::TraceExit),
            Received::TraceClose(_) => Ok(EventKind::TraceClose),
            Received::Rss(_) => Ok(EventKind::Rss),
            Received::Block(ev) => match ev.rw {
                0 => Ok(EventKind::BlockRead),
                1 => Ok(EventKind::BlockWrite),
                _ => anyhow::bail!("unknown block event type"),
            },
            Received::Vfs(ev) => match ev.rw {
                0 => Ok(EventKind::VfsRead),
                1 => Ok(EventKind::VfsWrite),
                _ => anyhow::bail!("unknown vfs event type"),
            },
            Received::UdpRecv(_) => Ok(EventKind::UdpRecv),
            Received::UdpSend(_) => Ok(EventKind::UdpSend),
            Received::TcpRecv(_) => Ok(EventKind::TcpRecv),
            Received::TcpSend(_) => Ok(EventKind::TcpSend),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Received<'a> {
    type Error = anyhow::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        anyhow::ensure!(!bytes.is_empty(), "empty event");
        match bytes[0] {
            0 => Ok(Received::Switch(to_event(bytes))),
            1 => Ok(Received::Profile(to_event(bytes))),
            2 => Ok(Received::TraceEnter(to_event(bytes))),
            3 => Ok(Received::TraceExit(to_event(bytes))),
            4 => Ok(Received::TraceClose(to_event(bytes))),
            5 => Ok(Received::ProcessExit(to_event(bytes))),
            6 => Ok(Received::ProcessExec(to_event(bytes))),
            7 => Ok(Received::Rss(to_event(bytes))),
            8 => Ok(Received::Block(to_event(bytes))),
            9 => Ok(Received::Vfs(to_event(bytes))),
            10 => Ok(Received::UdpRecv(to_event(bytes))),
            11 => Ok(Received::UdpSend(to_event(bytes))),
            12 => Ok(Received::TcpRecv(to_event(bytes))),
            13 => Ok(Received::TcpSend(to_event(bytes))),
            _ => anyhow::bail!("unknown event type"),
        }
    }
}

pub(crate) fn null_terminated(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

fn exe_name_and_change_time(tgid: u32) -> Result<(PathBuf, u64)> {
    let path = format!("/proc/{}/exe", tgid);
    let exe = fs::read_link(path)?;
    let meta = exe.metadata()?;
    let mtime = meta.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    Ok((exe, mtime))
}

fn exe_change_time_build_id(tgid: u32) -> Result<(PathBuf, u64, Bytes)> {
    let (exe, mtime) = exe_name_and_change_time(tgid)?;
    let build_id = read_elf_build_id(&exe)
        .context("read buildid")?
        .map(|buildid| Bytes::copy_from_slice(buildid.as_ref()))
        .unwrap_or_default();
    Ok((exe, mtime, build_id))
}
