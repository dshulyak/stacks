use std::{borrow::Cow, collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use blazesym::symbolize::{Reason, Sym, Symbolized};
use datafusion::{
    arrow::{
        array::{AsArray, ListArray, RecordBatch},
        datatypes::{UInt16Type, UInt32Type, UInt64Type},
    },
    common::{FileType, GetExt},
    datasource::{file_format::parquet::ParquetFormat, listing::ListingOptions},
    execution::context::SessionContext,
};
use itertools::{assert_equal, multizip};
use lazy_static::lazy_static;
use parquet::basic::Compression;
use proptest::{prelude::*, test_runner::Config};
use proptest_state_machine::{prop_state_machine, ReferenceStateMachine, StateMachineTest};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use crate::{
    collector::{null_terminated, to_bytes, Frames, Received, Symbolizer},
    past::past_types,
    program::{self, Program},
};

#[derive(Debug, Clone)]
pub enum Op {
    Switch(past_types::switch_event),
    Perf(past_types::perf_cpu_event),
}

impl Op {
    fn as_slice(&self) -> &[u8] {
        match self {
            Op::Switch(switch) => to_bytes(switch),
            Op::Perf(perf) => to_bytes(perf),
        }
    }
}

#[derive(Debug, Clone)]
struct Thread {
    tgid: i32,
    pid: i32,
    comm: String,
}

impl Thread {
    fn command(&self) -> [u8; 16] {
        let mut command = [0; 16];
        command[..self.comm.len()].copy_from_slice(self.comm.as_bytes());
        command
    }
}

lazy_static! {
    static ref SYMBOLS: HashMap<u64, &'static str> = {
        let mut map = HashMap::new();
        map.insert(1, "exnoinline::my_function1");
        map.insert(2, "exnoinline::my_function2");
        map.insert(3, "exnoinline::my_function3");
        map.insert(4, "exnoinline::my_function4");
        map
    };
}

#[derive(Debug, Clone)]
struct TestSymbolizer {
    symbols: HashMap<u64, &'static str>,
}

impl Symbolizer for TestSymbolizer {
    fn new() -> Self {
        TestSymbolizer {
            symbols: SYMBOLS.clone(),
        }
    }

    fn init_symbolizer(&mut self, _tgid: u32) -> anyhow::Result<()> {
        Ok(())
    }

    fn drop_symbolizer(&mut self, _tgid: u32) -> Result<()> {
        Ok(())
    }

    fn symbolize_kernel(&self, addrs: &[u64]) -> anyhow::Result<Vec<blazesym::symbolize::Symbolized>> {
        let rst = addrs
            .iter()
            .map(|addr| match self.symbols.get(addr) {
                Some(symbol) => Symbolized::Sym(Sym {
                    addr: *addr,
                    name: Cow::Borrowed(*symbol),
                    offset: 0,
                    size: None,
                    code_info: None,
                    inlined: Box::new([]),
                    _non_exhaustive: (),
                }),
                None => Symbolized::Unknown(Reason::MissingSyms),
            })
            .collect();
        Ok(rst)
    }

    fn symbolize_process(&self, _tgid: u32, addr: &[u64]) -> anyhow::Result<Vec<Symbolized>> {
        self.symbolize_kernel(addr)
    }
}

#[derive(Debug, Clone)]
pub struct HashMapFrames(HashMap<i32, Vec<u64>>);

impl Frames for Arc<HashMapFrames> {
    fn frames(&self, id: i32) -> Result<Vec<u64>> {
        self.0.get(&id).cloned().ok_or(anyhow::anyhow!("missing frames"))
    }
}

impl Frames for HashMapFrames {
    fn frames(&self, id: i32) -> Result<Vec<u64>> {
        self.0.get(&id).cloned().ok_or(anyhow::anyhow!("missing frames"))
    }
}

fn resolved(frames: &HashMapFrames, symbolizer: &TestSymbolizer, addr: i32) -> Vec<String> {
    let frames = match frames.frames(addr) {
        Ok(frames) => frames,
        Err(_) => return vec![],
    };
    let symbols = match symbolizer.symbolize_kernel(&frames) {
        Ok(symbols) => symbols,
        Err(_) => return vec![],
    };
    symbols
        .into_iter()
        .filter_map(|symbol| match symbol {
            Symbolized::Sym(sym) => Some(sym.name.to_string()),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct RefState {
    rows_in_file: usize,
    row_group_size: usize,
    threads: Vec<Thread>,

    frames: Arc<HashMapFrames>,
    symbolizer: TestSymbolizer,

    // last recorded timestamp on every cpu.
    // generally program will put events into the correct order if they are not emitted
    // in the expected order, however it will require additional cycles.
    timestamp_per_cpu: Vec<u64>,

    traces: Vec<past_types::switch_event>,
    stacks: Vec<past_types::perf_cpu_event>,

    persisted_traces: Vec<past_types::switch_event>,
    persisted_stacks: Vec<past_types::perf_cpu_event>,
}

impl RefState {
    fn persist(&mut self) {
        self.persisted_traces.append(&mut self.traces);
        self.persisted_stacks.append(&mut self.stacks);
        self.rows_in_file = 0;
    }
}

#[derive(Debug)]
pub struct RefModel;

impl ReferenceStateMachine for RefModel {
    type State = RefState;
    type Transition = Op;

    fn init_state() -> BoxedStrategy<Self::State> {
        let row_group = 10..60usize;
        let cores = 1..=16usize;
        let threads = (10..100i32)
            .prop_map(|tgid| {
                prop::collection::vec(
                    (Just(tgid), 0..100i32).prop_map(|(tgid, pid)| Thread {
                        tgid: tgid * 100,
                        pid: tgid * 100 + pid,
                        comm: format!("comm{}", tgid * 100 + pid),
                    }),
                    1..=20,
                )
            })
            .prop_flat_map(|group| group)
            .prop_map(|groups| groups.into_iter().collect::<Vec<_>>());

        let frames = (1..10i32, 0..=16usize)
            .prop_flat_map(|(id, size)| {
                prop::collection::vec(0..10u64, size).prop_map(move |frames| {
                    let mut map = HashMap::new();
                    map.insert(id, frames);
                    HashMapFrames(map)
                })
            })
            .boxed();

        (row_group, cores, threads, frames)
            .prop_map(|(row, cores, tgids, frames)| RefState {
                rows_in_file: 0,
                row_group_size: row,
                threads: tgids,
                frames: Arc::new(frames),
                symbolizer: TestSymbolizer::new(),
                timestamp_per_cpu: vec![10000; cores],
                traces: vec![],
                stacks: vec![],
                persisted_traces: vec![],
                persisted_stacks: vec![],
            })
            .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let threads = state.threads.clone();
        let cores = state.timestamp_per_cpu.clone();

        let switch = (
            (0..cores.len() as u16),
            3..1000u64,
            (0..threads.len()),
            (-1..15i32),
            (-1..15i32),
        )
            .prop_map(
                move |(cpu, duration, thread, ustack, kstack)| past_types::switch_event {
                    r#type: 0,
                    cpu_id: cpu as u32,
                    start: cores[cpu as usize],
                    end: cores[cpu as usize] + duration,
                    tgid: threads[thread].tgid as u32,
                    pid: threads[thread].pid as u32,
                    ustack,
                    kstack,
                    ..Default::default()
                },
            )
            .prop_map(Op::Switch);

        let threads = state.threads.clone();
        let cores = state.timestamp_per_cpu.clone();
        let stack = (
            (0..cores.len() as u32),
            1..1000u64,
            (0..threads.len()),
            (-1..15i32),
            (-1..15i32),
        )
            .prop_map(
                move |(cpu, duration, thread, ustack, kstack)| past_types::perf_cpu_event {
                    r#type: 1,
                    cpu_id: cpu,
                    timestamp: cores[cpu as usize] + duration,
                    tgid: threads[thread].tgid as u32,
                    pid: threads[thread].pid as u32,
                    ustack,
                    kstack,
                    ..Default::default()
                },
            )
            .prop_map(Op::Perf);

        prop_oneof![switch, stack].boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Op::Switch(switch) => {
                state.timestamp_per_cpu[switch.cpu_id as usize] = switch.end;
                state.traces.push(*switch);
                let mut i = state.traces.len() - 1;
                while i > 0 && state.traces[i].end < state.traces[i - 1].end {
                    state.traces.swap(i, i - 1);
                    i -= 1;
                }
            }
            Op::Perf(perf) => {
                state.timestamp_per_cpu[perf.cpu_id as usize] = perf.timestamp;
                if perf.ustack > 0 || perf.kstack > 0 {
                    state.stacks.push(*perf);
                    let mut i = state.stacks.len() - 1;
                    while i > 0 && state.stacks[i].timestamp < state.stacks[i - 1].timestamp {
                        state.stacks.swap(i, i - 1);
                        i -= 1;
                    }
                }
            }
        }
        state.rows_in_file += 1;
        if state.rows_in_file == state.row_group_size {
            state.persist();
        }
        state
    }
}

pub struct State {
    tempdir: TempDir,
    program: Program<Arc<HashMapFrames>, TestSymbolizer>,
}

impl State {
    fn new(groups_size: usize, frames: Arc<HashMapFrames>) -> Self {
        let tempdir = TempDir::with_prefix("trace-test-").expect("failed to crete tempdir");
        let cfg = program::Config {
            directory: tempdir.path().to_path_buf(),
            rows_per_group: groups_size,
            groups_per_file: 1,
            timestamp_adjustment: 0,
            perf_event_frequency: 99,
            compression: Compression::UNCOMPRESSED,
            _non_exhaustive: (),
        };
        let program = Program::new(cfg, frames, TestSymbolizer::new()).expect("failed to create program");
        State { tempdir, program }
    }
}

struct TestState;

impl StateMachineTest for TestState {
    type SystemUnderTest = State;
    type Reference = RefModel;

    fn init_test(ref_state: &RefState) -> Self::SystemUnderTest {
        let mut state = State::new(ref_state.row_group_size, ref_state.frames.clone());
        for thread in ref_state.threads.iter() {
            let fake_exec_event = past_types::process_exec_event {
                tgid: thread.tgid as u32,
                comm: thread.command(),
                ..Default::default()
            };
            state
                .program
                .on_event(Received::ProcessExec(&fake_exec_event))
                .expect("collected event");
        }
        state
    }

    fn apply(mut sut: Self::SystemUnderTest, _ref_state: &RefState, op: Op) -> Self::SystemUnderTest {
        sut.program.on_event(op.as_slice().into()).expect("collected event");
        sut
    }

    fn test_sequential(
        _config: Config,
        mut ref_state: RefState,
        transitions: Vec<Op>,
        seen_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) {
        let mut sut = Self::init_test(&ref_state);
        for transition in transitions {
            ref_state = Self::Reference::apply(ref_state, &transition);
            sut = Self::apply(sut, &ref_state, transition);
            if let Some(seen_counter) = seen_counter.as_ref() {
                seen_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        sut.program.exit_current_file().expect("succesfully exited");
        ref_state.persist();

        let rt = Runtime::new().unwrap();
        let ctx = rt
            .block_on(session(sut.tempdir.path()))
            .expect("failed to register collected files");
        rt.block_on(verify_switches(&ctx, &ref_state));
        rt.block_on(verify_perf(&ctx, &ref_state));
    }
}

async fn session(dir: &Path) -> Result<SessionContext> {
    let ctx = SessionContext::new();
    ctx.register_listing_table(
        "stacks",
        format!("{}/STACKS-*.parquet", dir.to_str().unwrap()),
        ListingOptions::new(Arc::new(ParquetFormat::default())).with_file_extension(FileType::PARQUET.get_ext()),
        None,
        None,
    )
    .await?;
    Ok(ctx)
}

async fn verify_switches(ctx: &SessionContext, ref_state: &RefState) {
    // show(ctx, SWITCH_QUERY_WITH_STACKS).await;
    // for trace in ref_state.persisted_traces.iter() {
    //     println!("{:?}", trace);
    // }

    let batch = read(ctx, SWITCH_QUERY_WITH_STACKS).await;
    let tgid_to_comm = ref_state
        .threads
        .iter()
        .map(|thread| (thread.tgid as u32, thread.command()))
        .collect::<HashMap<u32, [u8; 16]>>();
    let traces = ref_state.persisted_traces.iter().map(|switch| StoredSwitch {
        timestamp: switch.end,
        duration: switch.end - switch.start,
        cpu: switch.cpu_id as u64,
        tgid: switch.tgid as u64,
        pid: switch.pid as u64,
        command: String::from_utf8_lossy(null_terminated(&tgid_to_comm[&switch.tgid])).to_string(),
        ustack: resolved(&ref_state.frames, &ref_state.symbolizer, switch.ustack),
        kstack: resolved(&ref_state.frames, &ref_state.symbolizer, switch.kstack),
    });
    assert_equal(batch.iter_switch(), traces);
}

async fn verify_perf(ctx: &SessionContext, ref_state: &RefState) {
    // show(ctx, STACKS_QUERY).await;
    // for stack in ref_state.persisted_stacks.iter() {
    //     println!("{:?}", stack);
    // }

    let batch = read(ctx, STACKS_QUERY).await;
    let tgid_to_comm = ref_state
        .threads
        .iter()
        .map(|thread| (thread.tgid as u32, thread.command()))
        .collect::<HashMap<u32, [u8; 16]>>();
    let stacks = ref_state.persisted_stacks.iter().map(|perf| StoredPerf {
        timestamp: perf.timestamp,
        cpu: perf.cpu_id as u64,
        tgid: perf.tgid as u64,
        pid: perf.pid as u64,
        command: String::from_utf8_lossy(null_terminated(&tgid_to_comm[&perf.tgid])).to_string(),
        ustack: resolved(&ref_state.frames, &ref_state.symbolizer, perf.ustack),
        kstack: resolved(&ref_state.frames, &ref_state.symbolizer, perf.kstack),
    });
    assert_equal(batch.iter_perf(), stacks);
}

static SWITCH_QUERY_WITH_STACKS: &str = include_str!("tests_sql/switch_natural_order.sql");
static STACKS_QUERY: &str = include_str!("tests_sql/perf_natural_order.sql");

struct Batch(Vec<RecordBatch>);

#[derive(Debug, PartialEq)]
struct StoredSwitch {
    timestamp: u64,
    duration: u64,
    cpu: u64,
    tgid: u64,
    pid: u64,
    command: String,
    ustack: Vec<String>,
    kstack: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct StoredPerf {
    timestamp: u64,
    cpu: u64,
    tgid: u64,
    pid: u64,
    command: String,
    ustack: Vec<String>,
    kstack: Vec<String>,
}

impl Batch {
    fn iter_perf(&self) -> impl Iterator<Item = StoredPerf> + '_ {
        self.0.iter().flat_map(|batch| {
            let timestamp = batch.column(0).as_primitive::<UInt64Type>();
            let cpu = batch.column(1).as_primitive::<UInt16Type>();
            let tgid = batch.column(2).as_primitive::<UInt32Type>();
            let pid = batch.column(3).as_primitive::<UInt32Type>();
            let command = batch.column(4).as_string::<i32>();

            let ustack = batch.column(5);
            let ustack_array = ustack.as_any().downcast_ref::<ListArray>().unwrap();

            let kstack = batch.column(6);
            let kstack_array = kstack.as_any().downcast_ref::<ListArray>().unwrap();
            multizip((
                timestamp.values().iter(),
                cpu.values().iter(),
                tgid.values().iter(),
                pid.values().iter(),
                command,
                ustack_array.iter(),
                kstack_array.iter(),
            ))
            .map(|(timestamp, cpu, tgid, pid, command, ustack, kstack)| StoredPerf {
                timestamp: *timestamp,
                cpu: *cpu as u64,
                tgid: *tgid as u64,
                pid: *pid as u64,
                command: match command {
                    Some(command) => command.to_string(),
                    None => String::new(),
                },
                ustack: match ustack {
                    None => vec![],
                    Some(ustack) => {
                        let ustack = ustack.as_string::<i32>();
                        ustack
                            .iter()
                            .filter(|s| s.is_some())
                            .map(|s| s.unwrap().to_string())
                            .collect()
                    }
                },
                kstack: match kstack {
                    None => vec![],
                    Some(kstack) => {
                        let kstack = kstack.as_string::<i32>();
                        kstack
                            .iter()
                            .filter(|s| s.is_some())
                            .map(|s| s.unwrap().to_string())
                            .collect()
                    }
                },
            })
        })
    }

    fn iter_switch(&self) -> impl Iterator<Item = StoredSwitch> + '_ {
        self.0.iter().flat_map(|batch| {
            let timestamp = batch.column(0).as_primitive::<UInt64Type>();
            let duration = batch.column(1).as_primitive::<UInt64Type>();
            let cpu = batch.column(2).as_primitive::<UInt16Type>();
            let tgid = batch.column(3).as_primitive::<UInt32Type>();
            let pid = batch.column(4).as_primitive::<UInt32Type>();
            let command = batch.column(5).as_string::<i32>();

            let ustack = batch.column(6);
            let ustack_array = ustack.as_any().downcast_ref::<ListArray>().unwrap();

            let kstack = batch.column(7);
            let kstack_array = kstack.as_any().downcast_ref::<ListArray>().unwrap();

            multizip((
                timestamp.values().iter(),
                duration.values().iter(),
                cpu.values().iter(),
                tgid.values().iter(),
                pid.values().iter(),
                command,
                ustack_array.iter(),
                kstack_array.iter(),
            ))
            .map(
                |(timestamp, duration, cpu, tgid, pid, command, ustack, kstack)| StoredSwitch {
                    timestamp: *timestamp,
                    duration: *duration,
                    cpu: *cpu as u64,
                    tgid: *tgid as u64,
                    pid: *pid as u64,
                    command: match command {
                        Some(command) => command.to_string(),
                        None => String::new(),
                    },
                    ustack: match ustack {
                        None => vec![],
                        Some(ustack) => ustack
                            .as_string::<i32>()
                            .iter()
                            .filter_map(|s| s.map(|s| s.to_string()))
                            .collect(),
                    },
                    kstack: match kstack {
                        None => vec![],
                        Some(kstack) => kstack
                            .as_string::<i32>()
                            .iter()
                            .filter_map(|s| s.map(|s| s.to_string()))
                            .collect(),
                    },
                },
            )
        })
    }
}

async fn read(ctx: &SessionContext, query: &str) -> Batch {
    let df = ctx.sql(query).await.unwrap();
    Batch(df.collect().await.unwrap())
}

#[allow(dead_code)]
async fn show(ctx: &SessionContext, query: &str) {
    let df = ctx.sql(query).await.unwrap();
    df.show().await.unwrap();
}

prop_state_machine! {
    #![proptest_config(Config {
        cases: 100,
        verbose: 1,
        .. Config::default()
    })]
    #[test]
    fn test_state(sequential 10..50 => TestState);
}
