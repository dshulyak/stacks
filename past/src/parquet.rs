use std::{io::Write, sync::Arc};

use anyhow::{Context, Result};
use bytes::Bytes;
use parquet::{
    basic::{self, Encoding},
    data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type},
    file::{
        properties::{EnabledStatistics, WriterProperties},
        writer::SerializedFileWriter,
    },
    format::SortingColumn,
    schema::{parser::parse_message_type, types},
};
use tracing::instrument;

pub enum EventKind {
    // Perf collected from sampling process
    Perf,
    // Collected when process is switched out by the scheduler
    Switch,
    TraceExit,
    TraceClose,
}

impl From<EventKind> for &'static [u8] {
    fn from(kind: EventKind) -> &'static [u8] {
        match kind {
            EventKind::Perf => b"perf",
            EventKind::Switch => b"switch",
            EventKind::TraceExit => b"trace_exit",
            EventKind::TraceClose => b"trace_close",
        }
    }
}

impl From<EventKind> for Bytes {
    fn from(kind: EventKind) -> Bytes {
        Bytes::from_static(kind.into())
    }
}

impl From<EventKind> for ByteArray {
    fn from(kind: EventKind) -> ByteArray {
        let byts: Bytes = kind.into();
        byts.into()
    }
}

fn events_schema() -> types::Type {
    parse_message_type(
        "
    message Stack {
        required int64 timestamp (INTEGER(64, false));
        required int64 duration (INTEGER(64, false));
        required binary kind (UTF8);
        required int32 cpu (INTEGER(16, false));
        required int32 tgid (INTEGER(32, false));
        required int32 pid (INTEGER(32, false));
        required int64 span_id (INTEGER(64, false));
        required int64 parent_id (INTEGER(64, false));
        required int64 work_id (INTEGER(64, false));
        required int64 amount (INTEGER(64, false));
        required binary command (UTF8);
        required binary trace_name (UTF8);
        repeated binary ustack (UTF8);
        repeated binary kstack (UTF8);
    }
    ",
    )
    .expect("schema should compile")
}

#[derive(Debug)]
pub enum Event {
    Switch {
        ts: i64,
        duration: i64,
        cpu: i32,
        tgid: i32,
        pid: i32,
        command: Bytes,
        ustack: i32,
        kstack: i32,
    },
    CPUStack {
        ts: i64,
        cpu: i32,
        tgid: i32,
        pid: i32,
        command: Bytes,
        ustack: i32,
        kstack: i32,
    },
    TraceExit {
        ts: i64,
        duration: i64,
        cpu: i32,
        tgid: i32,
        pid: i32,
        span_id: i64,
        parent_id: i64,
        work_id: i64,
        amount: i64,
        name: Bytes,
        command: Bytes,
        ustack: i32,
    },
    TraceClose {
        ts: i64,
        duration: i64,
        cpu: i32,
        tgid: i32,
        pid: i32,
        span_id: i64,
        parent_id: i64,
        work_id: i64,
        amount: i64,
        name: Bytes,
        command: Bytes,
    },
}

#[derive(Debug)]
pub struct Group {
    max_timestamp: i64,
    timestamp_adjustment: u64,
    perf_freq: i64,

    timestamp: Vec<i64>,
    duration: Vec<i64>,
    kind: Vec<ByteArray>,
    cpu: Vec<i32>,
    tgid: Vec<i32>,
    pid: Vec<i32>,
    span_id: Vec<i64>,
    parent_id: Vec<i64>,
    work_id: Vec<i64>,
    amount: Vec<i64>,
    command: Vec<ByteArray>,
    trace_name: Vec<ByteArray>,

    ustack: RepeatedStack,
    kstack: RepeatedStack,

    unresolved_ustack: Vec<i32>,
    unresolved_kstack: Vec<i32>,
}

impl Group {
    pub(crate) fn new(capacity: usize, timestamp_adjustment: u64, perf_freq: i64) -> Self {
        Self {
            max_timestamp: i64::MIN,
            timestamp_adjustment,
            perf_freq,
            timestamp: Vec::with_capacity(capacity),
            duration: Vec::with_capacity(capacity),
            kind: Vec::with_capacity(capacity),
            cpu: Vec::with_capacity(capacity),
            tgid: Vec::with_capacity(capacity),
            pid: Vec::with_capacity(capacity),
            span_id: Vec::with_capacity(capacity),
            parent_id: Vec::with_capacity(capacity),
            work_id: Vec::with_capacity(capacity),
            amount: Vec::with_capacity(capacity),
            command: Vec::with_capacity(capacity),
            trace_name: Vec::with_capacity(capacity),
            ustack: RepeatedStack {
                stacks: Vec::with_capacity(capacity),
                repetition_levels: Vec::with_capacity(capacity),
                definition_levels: Vec::with_capacity(capacity),
            },
            kstack: RepeatedStack {
                stacks: Vec::with_capacity(capacity),
                repetition_levels: Vec::with_capacity(capacity),
                definition_levels: Vec::with_capacity(capacity),
            },
            unresolved_ustack: Vec::with_capacity(capacity),
            unresolved_kstack: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.timestamp.len() >= self.timestamp.capacity()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
    }

    fn add_timestamp(&mut self, ts: i64) {
        let ts = ts + self.timestamp_adjustment as i64;
        self.timestamp.push(ts);
        self.max_timestamp = self.max_timestamp.max(ts);
        if ts != self.max_timestamp {
            // find correct position for new record
            // the events are emitted in the order each cpu processes them
            // however there could be
            let len = self.timestamp.len();
            let mut i = len - 1;
            while i > 0 && self.timestamp[i - 1] > ts {
                self.timestamp.swap(i, i - 1);
                self.duration.swap(i, i - 1);
                self.kind.swap(i, i - 1);
                self.cpu.swap(i, i - 1);
                self.tgid.swap(i, i - 1);
                self.pid.swap(i, i - 1);
                self.span_id.swap(i, i - 1);
                self.parent_id.swap(i, i - 1);
                self.work_id.swap(i, i - 1);
                self.amount.swap(i, i - 1);
                self.command.swap(i, i - 1);
                self.trace_name.swap(i, i - 1);
                self.unresolved_kstack.swap(i, i - 1);
                self.unresolved_ustack.swap(i, i - 1);
                i -= 1;
            }
        }
    }

    pub(crate) fn collect(&mut self, event: Event) {
        match event {
            Event::Switch {
                ts,
                duration,
                cpu,
                tgid,
                pid,
                command,
                ustack,
                kstack,
            } => {
                self.duration.push(duration);
                self.kind.push(EventKind::Switch.into());
                self.cpu.push(cpu);
                self.tgid.push(tgid);
                self.pid.push(pid);
                self.command.push(command.into());
                self.unresolved_kstack.push(kstack);
                self.unresolved_ustack.push(ustack);
                self.add_empty_trace();
                self.add_timestamp(ts);
            }
            Event::CPUStack {
                ts,
                cpu,
                tgid,
                pid,
                command,
                ustack,
                kstack,
            } => {
                self.duration.push(self.perf_freq);
                self.kind.push(EventKind::Perf.into());
                self.cpu.push(cpu);
                self.tgid.push(tgid);
                self.pid.push(pid);
                self.command.push(command.into());
                self.unresolved_ustack.push(ustack);
                self.unresolved_kstack.push(kstack);
                self.add_empty_trace();
                self.add_timestamp(ts);
            }
            Event::TraceExit {
                ts,
                duration,
                cpu,
                tgid,
                pid,
                span_id,
                parent_id,
                work_id,
                amount,
                name,
                command,
                ustack,
            } => {
                self.duration.push(duration);
                self.kind.push(EventKind::TraceExit.into());
                self.cpu.push(cpu);
                self.tgid.push(tgid);
                self.pid.push(pid);
                self.span_id.push(span_id);
                self.parent_id.push(parent_id);
                self.work_id.push(work_id);
                self.amount.push(amount);
                self.command.push(command.into());
                self.trace_name.push(name.into());
                self.unresolved_kstack.push(0);
                self.unresolved_ustack.push(ustack);
                self.add_timestamp(ts);
            }
            Event::TraceClose {
                ts,
                duration,
                cpu,
                tgid,
                pid,
                span_id,
                parent_id,
                work_id,
                amount,
                name,
                command,
            } => {
                self.duration.push(duration);
                self.kind.push(EventKind::TraceClose.into());
                self.cpu.push(cpu);
                self.tgid.push(tgid);
                self.pid.push(pid);
                self.span_id.push(span_id);
                self.parent_id.push(parent_id);
                self.work_id.push(work_id);
                self.amount.push(amount);
                self.command.push(command.into());
                self.trace_name.push(name.into());
                self.unresolved_kstack.push(0);
                self.unresolved_ustack.push(0);
                self.add_timestamp(ts);
            }
        }
    }

    pub(crate) fn reuse(&mut self) {
        self.max_timestamp = i64::MIN;
        self.timestamp.clear();
        self.duration.clear();
        self.kind.clear();
        self.cpu.clear();
        self.tgid.clear();
        self.pid.clear();
        self.span_id.clear();
        self.parent_id.clear();
        self.work_id.clear();
        self.amount.clear();
        self.command.clear();
        self.trace_name.clear();
        self.ustack.stacks.clear();
        self.ustack.repetition_levels.clear();
        self.ustack.definition_levels.clear();
        self.kstack.stacks.clear();
        self.kstack.repetition_levels.clear();
        self.kstack.definition_levels.clear();
        self.unresolved_ustack.clear();
        self.unresolved_kstack.clear();
    }

    fn add_empty_trace(&mut self) {
        self.span_id.push(0);
        self.parent_id.push(0);
        self.work_id.push(0);
        self.amount.push(0);
        self.trace_name.push(Bytes::new().into());
    }

    pub(crate) fn unresolved_ustacks(&self) -> impl Iterator<Item = (i32, i32)> + '_ {
        let resolved = self.tgid.len() - self.unresolved_ustack.len();
        let tgid = self.tgid[resolved..].iter().copied();
        tgid.zip(self.unresolved_ustack.iter().copied())
    }

    pub(crate) fn unresolved_kstacks(&self) -> impl Iterator<Item = i32> + '_ {
        self.unresolved_kstack.iter().copied()
    }

    pub(crate) fn resolve(&mut self, ustacks: impl Iterator<Item = Bytes>, kstacks: impl Iterator<Item = Bytes>) {
        let mut rep_level = 0;
        for stack in ustacks {
            self.ustack.repetition_levels.push(rep_level);
            rep_level = 1;
            self.ustack.definition_levels.push(1);
            self.ustack.stacks.push(stack.into());
        }
        if rep_level == 0 {
            self.ustack.repetition_levels.push(0);
            self.ustack.definition_levels.push(0);
        }

        rep_level = 0;
        for stack in kstacks {
            self.kstack.repetition_levels.push(rep_level);
            rep_level = 1;
            self.kstack.definition_levels.push(1);
            self.kstack.stacks.push(stack.into());
        }
        if rep_level == 0 {
            self.kstack.repetition_levels.push(0);
            self.kstack.definition_levels.push(0);
        }
    }
}

#[derive(Debug)]
pub struct GroupWriter<W: Write + Send>(SerializedFileWriter<W>);

impl<W: Write + Send> GroupWriter<W> {
    pub(crate) fn with_compression(writer: W, compression: Compression) -> Result<Self> {
        let schema = Arc::new(events_schema());
        let properties = Arc::new(
            WriterProperties::builder()
                .set_compression(compression)
                .set_column_dictionary_enabled("timestamp".into(), false)
                .set_column_encoding("timestamp".into(), Encoding::DELTA_BINARY_PACKED)
                .set_column_statistics_enabled("timestamp".into(), EnabledStatistics::Page)
                .set_sorting_columns(Some(vec![SortingColumn {
                    column_idx: 0,
                    descending: false,
                    nulls_first: true, // there should be no nulls
                }]))
                .build(),
        );
        let writer = SerializedFileWriter::new(writer, schema, properties)?;
        Ok(Self(writer))
    }

    #[instrument(skip_all)]
    pub(crate) fn write(&mut self, group: &Group) -> Result<()> {
        let mut rows = self.0.next_row_group()?;
        let mut timestamp = rows.next_column()?.expect("timestamp column");
        timestamp
            .typed::<Int64Type>()
            .write_batch(&group.timestamp, None, None)
            .context("timestamp")?;
        timestamp.close()?;

        let mut duration = rows.next_column()?.expect("duration column");
        duration
            .typed::<Int64Type>()
            .write_batch(&group.duration, None, None)
            .context("duration")?;
        duration.close()?;

        let mut kind = rows.next_column()?.expect("kind column");
        kind.typed::<ByteArrayType>()
            .write_batch(&group.kind, None, None)
            .context("kind")?;
        kind.close()?;

        let mut cpu = rows.next_column()?.expect("cpu column");
        cpu.typed::<Int32Type>()
            .write_batch(&group.cpu, None, None)
            .context("cpu")?;
        cpu.close()?;

        let mut tgid = rows.next_column()?.expect("tgid column");
        tgid.typed::<Int32Type>()
            .write_batch(&group.tgid, None, None)
            .context("tgid")?;
        tgid.close()?;

        let mut pid = rows.next_column()?.expect("pid column");
        pid.typed::<Int32Type>()
            .write_batch(&group.pid, None, None)
            .context("pid")?;
        pid.close()?;

        let mut span_id = rows.next_column()?.expect("span_id column");
        span_id
            .typed::<Int64Type>()
            .write_batch(&group.span_id, None, None)
            .context("span_id")?;
        span_id.close()?;

        let mut parent_id = rows.next_column()?.expect("parent_id column");
        parent_id
            .typed::<Int64Type>()
            .write_batch(&group.parent_id, None, None)
            .context("parent_id")?;
        parent_id.close()?;

        let mut work_id = rows.next_column()?.expect("work_id column");
        work_id
            .typed::<Int64Type>()
            .write_batch(&group.work_id, None, None)
            .context("work_id")?;
        work_id.close()?;

        let mut amount = rows.next_column()?.expect("amount column");
        amount
            .typed::<Int64Type>()
            .write_batch(&group.amount, None, None)
            .context("amount")?;
        amount.close()?;

        let mut command = rows.next_column()?.expect("command column");
        command
            .typed::<ByteArrayType>()
            .write_batch(&group.command, None, None)
            .context("command")?;
        command.close()?;

        let mut trace_name = rows.next_column()?.expect("trace_name column");
        trace_name
            .typed::<ByteArrayType>()
            .write_batch(&group.trace_name, None, None)
            .context("trace_name")?;
        trace_name.close()?;

        let mut ustack = rows.next_column()?.expect("ustack column");
        ustack
            .typed::<ByteArrayType>()
            .write_batch(
                &group.ustack.stacks,
                Some(&group.ustack.definition_levels),
                Some(&group.ustack.repetition_levels),
            )
            .context("ustack")?;
        ustack.close().context("close ustack")?;

        let mut kstack = rows.next_column()?.expect("kstack column");
        kstack
            .typed::<ByteArrayType>()
            .write_batch(
                &group.kstack.stacks,
                Some(&group.kstack.definition_levels),
                Some(&group.kstack.repetition_levels),
            )
            .context("kstack")?;
        kstack.close().context("close kstack")?;

        rows.close().context("close rows")?;
        Ok(())
    }

    pub(crate) fn close(self) -> Result<()> {
        self.0.close()?;
        Ok(())
    }
}

#[derive(Debug)]
struct RepeatedStack {
    stacks: Vec<ByteArray>,
    repetition_levels: Vec<i16>,
    definition_levels: Vec<i16>,
}

pub type Compression = basic::Compression;
