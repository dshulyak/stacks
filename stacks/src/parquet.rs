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

#[derive(Debug)]
pub(crate) enum EventKind {
    Profile,
    Switch,
    Rss,
    TraceExit,
    TraceClose,
    BlockRead,
    BlockWrite,
    VfsRead,
    VfsWrite,
    UdpRecv,
    UdpSend,
    TcpRecv,
    TcpSend,
}

impl From<EventKind> for &'static [u8] {
    fn from(kind: EventKind) -> &'static [u8] {
        match kind {
            EventKind::Profile => b"profile",
            EventKind::Switch => b"switch",
            EventKind::Rss => b"rss",
            EventKind::TraceExit => b"trace_exit",
            EventKind::TraceClose => b"trace_close",
            EventKind::BlockRead => b"blk_read",
            EventKind::BlockWrite => b"blk_write",
            EventKind::VfsRead => b"vfs_read",
            EventKind::VfsWrite => b"vfs_write",
            EventKind::UdpRecv => b"udp_recv",
            EventKind::UdpSend => b"udp_send",
            EventKind::TcpRecv => b"tcp_recv",
            EventKind::TcpSend => b"tcp_send",
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
        required int64 id (INTEGER(64, false));
        required int64 amount (INTEGER(64, false));
        required binary command (UTF8);
        required binary trace_name (UTF8);
        required binary buildid;
        repeated group ustack {
            required binary name (UTF8);
            required int64 address (INTEGER(64, false));
            required int64 offset (INTEGER(64, false));
        }
        repeated group kstack {
            required binary name (UTF8);
            required int64 address (INTEGER(64, false));
            required int64 offset (INTEGER(64, false));
        }
    }
    ",
    )
    .expect("schema should compile")
}

#[derive(Debug)]
pub(crate) struct Event {
    pub(crate) ts: i64,
    pub(crate) duration: i64,
    pub(crate) kind: EventKind,
    pub(crate) cpu: i32,
    pub(crate) tgid: i32,
    pub(crate) pid: i32,
    pub(crate) span_id: i64,
    pub(crate) parent_id: i64,
    pub(crate) id: i64,
    pub(crate) amount: i64,
    pub(crate) command: Bytes,
    pub(crate) trace_name: Bytes,
    pub(crate) buildid: Bytes,
    pub(crate) ustack: i32,
    pub(crate) kstack: i32,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            ts: 0,
            duration: 0,
            kind: EventKind::Profile,
            cpu: 0,
            tgid: 0,
            pid: 0,
            span_id: 0,
            parent_id: 0,
            id: 0,
            amount: 0,
            command: Bytes::new(),
            trace_name: Bytes::new(),
            buildid: Bytes::new(),
            // -1 since 0 is a valid stack id
            ustack: -1,
            kstack: -1,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Group {
    timestamp: Vec<i64>,
    duration: Vec<i64>,
    kind: Vec<ByteArray>,
    cpu: Vec<i32>,
    tgid: Vec<i32>,
    pid: Vec<i32>,
    span_id: Vec<i64>,
    parent_id: Vec<i64>,
    id: Vec<i64>,
    amount: Vec<i64>,
    command: Vec<ByteArray>,
    trace_name: Vec<ByteArray>,
    buildid: Vec<ByteArray>,

    ustack: SymbolizedStack,
    kstack: SymbolizedStack,

    raw_ustack: Vec<i32>,
    raw_kstack: Vec<i32>,
}

pub(crate) struct WriteableGroup<'a> {
    timestamp: &'a mut Vec<i64>,
    duration: &'a mut Vec<i64>,
    kind: &'a mut Vec<ByteArray>,
    cpu: &'a mut Vec<i32>,
    tgid: &'a mut Vec<i32>,
    pid: &'a mut Vec<i32>,
    span_id: &'a mut Vec<i64>,
    parent_id: &'a mut Vec<i64>,
    id: &'a mut Vec<i64>,
    amount: &'a mut Vec<i64>,
    command: &'a mut Vec<ByteArray>,
    trace_name: &'a mut Vec<ByteArray>,
    buildid: &'a mut Vec<ByteArray>,
    ustack: &'a mut SymbolizedStack,
    kstack: &'a mut SymbolizedStack,
}

impl Drop for WriteableGroup<'_> {
    fn drop(&mut self) {
        self.timestamp.clear();
        self.duration.clear();
        self.kind.clear();
        self.cpu.clear();
        self.tgid.clear();
        self.pid.clear();
        self.span_id.clear();
        self.parent_id.clear();
        self.id.clear();
        self.amount.clear();
        self.command.clear();
        self.trace_name.clear();
        self.buildid.clear();
        self.ustack.name.clear();
        self.ustack.address.clear();
        self.ustack.offset.clear();
        self.ustack.repetition_levels.clear();
        self.ustack.definition_levels.clear();
        self.kstack.name.clear();
        self.kstack.address.clear();
        self.kstack.offset.clear();
        self.kstack.repetition_levels.clear();
        self.kstack.definition_levels.clear();
    }
}

impl Group {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            timestamp: Vec::with_capacity(capacity),
            duration: Vec::with_capacity(capacity),
            kind: Vec::with_capacity(capacity),
            cpu: Vec::with_capacity(capacity),
            tgid: Vec::with_capacity(capacity),
            pid: Vec::with_capacity(capacity),
            span_id: Vec::with_capacity(capacity),
            parent_id: Vec::with_capacity(capacity),
            id: Vec::with_capacity(capacity),
            amount: Vec::with_capacity(capacity),
            command: Vec::with_capacity(capacity),
            trace_name: Vec::with_capacity(capacity),
            buildid: Vec::with_capacity(capacity),
            ustack: SymbolizedStack {
                name: Vec::with_capacity(capacity),
                address: Vec::with_capacity(capacity),
                offset: Vec::with_capacity(capacity),
                repetition_levels: Vec::with_capacity(capacity),
                definition_levels: Vec::with_capacity(capacity),
            },
            kstack: SymbolizedStack {
                name: Vec::with_capacity(capacity),
                address: Vec::with_capacity(capacity),
                offset: Vec::with_capacity(capacity),
                repetition_levels: Vec::with_capacity(capacity),
                definition_levels: Vec::with_capacity(capacity),
            },
            raw_ustack: Vec::with_capacity(capacity),
            raw_kstack: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.timestamp.len() >= self.timestamp.capacity()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
    }

    pub(crate) fn save_event(&mut self, event: Event) {
        let Event {
            ts,
            duration,
            kind,
            cpu,
            tgid,
            pid,
            span_id,
            parent_id,
            id,
            amount,
            command,
            trace_name,
            buildid,
            ustack,
            kstack,
        } = event;
        self.timestamp.push(ts);
        self.duration.push(duration);
        self.kind.push(kind.into());
        self.cpu.push(cpu);
        self.tgid.push(tgid);
        self.pid.push(pid);
        self.span_id.push(span_id);
        self.parent_id.push(parent_id);
        self.id.push(id);
        self.amount.push(amount);
        self.command.push(command.into());
        self.trace_name.push(trace_name.into());
        self.buildid.push(buildid.into());
        self.raw_ustack.push(ustack);
        self.raw_kstack.push(kstack);

        // find correct position for new record
        // the events are emitted in the order each cpu processes them
        let mut i = self.timestamp.len() - 1;
        while i > 0 && self.timestamp[i - 1] > ts {
            self.timestamp.swap(i, i - 1);
            self.duration.swap(i, i - 1);
            self.kind.swap(i, i - 1);
            self.cpu.swap(i, i - 1);
            self.tgid.swap(i, i - 1);
            self.pid.swap(i, i - 1);
            self.span_id.swap(i, i - 1);
            self.parent_id.swap(i, i - 1);
            self.id.swap(i, i - 1);
            self.amount.swap(i, i - 1);
            self.command.swap(i, i - 1);
            self.trace_name.swap(i, i - 1);
            self.buildid.swap(i, i - 1);
            self.raw_kstack.swap(i, i - 1);
            self.raw_ustack.swap(i, i - 1);
            i -= 1;
        }
    }

    pub(crate) fn for_writing(&mut self) -> WriteableGroup {
        assert!(self.raw_kstack.is_empty(), "kstacks were not symbolized");
        assert!(self.raw_ustack.is_empty(), "ustacks were not symbolized");
        WriteableGroup {
            timestamp: &mut self.timestamp,
            duration: &mut self.duration,
            kind: &mut self.kind,
            cpu: &mut self.cpu,
            tgid: &mut self.tgid,
            pid: &mut self.pid,
            span_id: &mut self.span_id,
            parent_id: &mut self.parent_id,
            id: &mut self.id,
            amount: &mut self.amount,
            command: &mut self.command,
            trace_name: &mut self.trace_name,
            buildid: &mut self.buildid,
            ustack: &mut self.ustack,
            kstack: &mut self.kstack,
        }
    }

    pub(crate) fn raw_ustacks(&self) -> impl Iterator<Item = (i32, i32)> + '_ {
        let resolved = self.tgid.len() - self.raw_ustack.len();
        let tgid = self.tgid[resolved..].iter().copied();
        tgid.zip(self.raw_ustack.iter().copied())
    }

    pub(crate) fn raw_kstacks(&self) -> impl Iterator<Item = i32> + '_ {
        self.raw_kstack.iter().copied()
    }

    pub(crate) fn update_stacks_with_symbolized<'a>(
        &mut self,
        ustacks: impl Iterator<Item = &'a ResolvedStack>,
        kstacks: impl Iterator<Item = &'a ResolvedStack>,
    ) {
        self.raw_kstack.clear();
        self.raw_ustack.clear();
        let mut rep_level = 0;
        for stack in ustacks {
            self.ustack.repetition_levels.push(rep_level);
            rep_level = 1;
            self.ustack.definition_levels.push(1);
            self.ustack.name.push(stack.name.clone().into());
            self.ustack.address.push(stack.address as i64);
            self.ustack.offset.push(stack.offset as i64);
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
            self.kstack.name.push(stack.name.clone().into());
            self.kstack.address.push(stack.address as i64);
            self.kstack.offset.push(stack.offset as i64);
        }
        if rep_level == 0 {
            self.kstack.repetition_levels.push(0);
            self.kstack.definition_levels.push(0);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ResolvedStack {
    name: Bytes,
    address: u64,
    offset: u64,
}

impl ResolvedStack {
    pub(crate) fn new(name: Bytes, address: u64, offset: u64) -> Self {
        Self { name, address, offset }
    }
}

#[derive(Debug)]
pub(crate) struct GroupWriter<W: Write + Send>(SerializedFileWriter<W>);

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
    pub(crate) fn write(&mut self, group: WriteableGroup) -> Result<()> {
        let mut rows = self.0.next_row_group()?;
        let mut timestamp = rows.next_column()?.expect("timestamp column");
        timestamp
            .typed::<Int64Type>()
            .write_batch(group.timestamp, None, None)
            .context("timestamp")?;
        timestamp.close()?;

        let mut duration = rows.next_column()?.expect("duration column");
        duration
            .typed::<Int64Type>()
            .write_batch(group.duration, None, None)
            .context("duration")?;
        duration.close()?;

        let mut kind = rows.next_column()?.expect("kind column");
        kind.typed::<ByteArrayType>()
            .write_batch(group.kind, None, None)
            .context("kind")?;
        kind.close()?;

        let mut cpu = rows.next_column()?.expect("cpu column");
        cpu.typed::<Int32Type>()
            .write_batch(group.cpu, None, None)
            .context("cpu")?;
        cpu.close()?;

        let mut tgid = rows.next_column()?.expect("tgid column");
        tgid.typed::<Int32Type>()
            .write_batch(group.tgid, None, None)
            .context("tgid")?;
        tgid.close()?;

        let mut pid = rows.next_column()?.expect("pid column");
        pid.typed::<Int32Type>()
            .write_batch(group.pid, None, None)
            .context("pid")?;
        pid.close()?;

        let mut span_id = rows.next_column()?.expect("span_id column");
        span_id
            .typed::<Int64Type>()
            .write_batch(group.span_id, None, None)
            .context("span_id")?;
        span_id.close()?;

        let mut parent_id = rows.next_column()?.expect("parent_id column");
        parent_id
            .typed::<Int64Type>()
            .write_batch(group.parent_id, None, None)
            .context("parent_id")?;
        parent_id.close()?;

        let mut id = rows.next_column()?.expect("id column");
        id.typed::<Int64Type>()
            .write_batch(group.id, None, None)
            .context("id")?;
        id.close()?;

        let mut amount = rows.next_column()?.expect("amount column");
        amount
            .typed::<Int64Type>()
            .write_batch(group.amount, None, None)
            .context("amount")?;
        amount.close()?;

        let mut command = rows.next_column()?.expect("command column");
        command
            .typed::<ByteArrayType>()
            .write_batch(group.command, None, None)
            .context("command")?;
        command.close()?;

        let mut trace_name = rows.next_column()?.expect("trace_name column");
        trace_name
            .typed::<ByteArrayType>()
            .write_batch(group.trace_name, None, None)
            .context("trace_name")?;
        trace_name.close()?;

        let mut builids = rows.next_column()?.expect("blobs column");
        builids
            .typed::<ByteArrayType>()
            .write_batch(group.buildid, None, None)
            .context("blobs")?;
        builids.close()?;

        let mut ustack_name = rows.next_column()?.expect("ustack column");
        ustack_name
            .typed::<ByteArrayType>()
            .write_batch(
                &group.ustack.name,
                Some(&group.ustack.definition_levels),
                Some(&group.ustack.repetition_levels),
            )
            .context("ustack")?;
        ustack_name.close().context("close ustack")?;

        let mut ustack_address = rows.next_column()?.expect("ustack_address column");
        ustack_address
            .typed::<Int64Type>()
            .write_batch(
                &group.ustack.address,
                Some(&group.ustack.definition_levels),
                Some(&group.ustack.repetition_levels),
            )
            .context("ustack_address")?;
        ustack_address.close().context("close ustack_address")?;

        let mut ustack_offset = rows.next_column()?.expect("ustack_offset column");
        ustack_offset
            .typed::<Int64Type>()
            .write_batch(
                &group.ustack.offset,
                Some(&group.ustack.definition_levels),
                Some(&group.ustack.repetition_levels),
            )
            .context("ustack_offset")?;
        ustack_offset.close().context("close ustack_offset")?;

        let mut kstack_name = rows.next_column()?.expect("kstack column");
        kstack_name
            .typed::<ByteArrayType>()
            .write_batch(
                &group.kstack.name,
                Some(&group.kstack.definition_levels),
                Some(&group.kstack.repetition_levels),
            )
            .context("kstack")?;
        kstack_name.close().context("close kstack")?;

        let mut kstack_address = rows.next_column()?.expect("kstack_address column");
        kstack_address
            .typed::<Int64Type>()
            .write_batch(
                &group.kstack.address,
                Some(&group.kstack.definition_levels),
                Some(&group.kstack.repetition_levels),
            )
            .context("kstack_address")?;
        kstack_address.close().context("close kstack_address")?;

        let mut kstack_offset = rows.next_column()?.expect("kstack_offset column");
        kstack_offset
            .typed::<Int64Type>()
            .write_batch(
                &group.kstack.offset,
                Some(&group.kstack.definition_levels),
                Some(&group.kstack.repetition_levels),
            )
            .context("kstack_offset")?;
        kstack_offset.close().context("close kstack_offset")?;

        rows.close().context("close rows")?;
        Ok(())
    }

    pub(crate) fn close(self) -> Result<()> {
        self.0.close()?;
        Ok(())
    }
}

#[derive(Debug)]
struct SymbolizedStack {
    name: Vec<ByteArray>,
    address: Vec<i64>,
    offset: Vec<i64>,
    repetition_levels: Vec<i16>,
    definition_levels: Vec<i16>,
}

pub(crate) type Compression = basic::Compression;
