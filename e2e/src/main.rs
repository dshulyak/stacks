use std::{
    collections::HashMap,
    path::PathBuf,
    process::{Child, Command},
    sync::Arc,
    thread::sleep,
    time::Duration,
};

use clap::Parser;
use datafusion::{
    arrow::{
        array::{Array, AsArray, ListArray, RecordBatch},
        datatypes::{Int32Type, Int64Type},
    },
    common::{FileType, GetExt},
    datasource::{file_format::parquet::ParquetFormat, listing::ListingOptions},
    execution::context::SessionContext,
};
use itertools::multizip;
use nix::{sys::signal, unistd::Pid};
use once_cell::sync::Lazy;
use proptest::{prelude::*, test_runner::Config};
use proptest_state_machine::{prop_state_machine, ReferenceStateMachine, StateMachineTest};
use tempfile::TempDir;
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(index(1), help = "path to the past binary")]
    past_binary: PathBuf,
    #[clap(index(2), help = "path to the examples binaries used in testinng")]
    examples_binaries: PathBuf,
    #[clap(long, default_value_t = false, help = "print sql output used in validation")]
    print_sql: bool,
}

impl Opt {
    fn example_path(&self, name: &str) -> PathBuf {
        self.examples_binaries.join(name)
    }
}

static CONFIG: Lazy<Opt> = Lazy::new(Opt::parse);

prop_state_machine! {
    #![proptest_config(Config {
        cases: 5,
        max_shrink_iters: 10,
        verbose: 1,
        .. Config::default()
    })]
    fn run_tracer_test(sequential 100..200 => System);
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    assert!(
        CONFIG.past_binary.exists(),
        "past binary at path {} does not exist",
        CONFIG.past_binary.display()
    );
    assert!(
        CONFIG.example_path(Sleeper::expected_comm()).exists(),
        "sleeper binary at path {} does not exist",
        CONFIG.example_path(Sleeper::expected_comm()).display()
    );
    assert!(
        CONFIG.example_path(Locker::expected_comm()).exists(),
        "locker binary at path {} does not exist",
        CONFIG.example_path(Locker::expected_comm()).display()
    );
    run_tracer_test();
    info!("tests passed");
}

#[derive(Debug, Clone)]
struct Sleeper {
    args: SleeperArgs,
}

#[derive(Debug, Clone)]
struct SleeperArgs {
    thread_count: usize,
    times: usize,
    sleep_for: Duration,
}

impl Sleeper {
    fn expected_comm() -> &'static str {
        "sleep"
    }

    fn spawn(&self) -> Child {
        Command::new(CONFIG.example_path(Self::expected_comm()))
            .arg(self.args.thread_count.to_string())
            .arg(self.args.times.to_string())
            .arg(self.args.sleep_for.as_millis().to_string())
            .spawn()
            .expect("failed to spawn process")
    }

    async fn verify(&self, dfctx: &SessionContext, _tgid: u32) {
        dfctx.sql("select 1").await.unwrap();
    }
}

#[derive(Debug, Clone)]
struct Locker {
    sleep_after_lock: Duration,
}

const OFFCPU_SWITCH_BY_TGID: &str = include_str!("../sql/offcpu_switch_by_tgid.sql");

impl Locker {
    fn expected_comm() -> &'static str {
        "lock"
    }

    fn new(sleep_after_lock: Duration) -> Self {
        Self { sleep_after_lock }
    }

    fn spawn(&self) -> Child {
        Command::new(CONFIG.example_path(Self::expected_comm()))
            .arg(self.sleep_after_lock.as_millis().to_string())
            .spawn()
            .expect("failed to spawn process")
    }

    async fn verify(&self, dfctx: &SessionContext, tgid: u32) {
        let query = OFFCPU_SWITCH_BY_TGID.replace("?tgid", &tgid.to_string());

        if CONFIG.print_sql {
            dfctx.sql(&query).await.unwrap().show().await.unwrap();
        }

        let rst = OffcpuDataFrame(dfctx.sql(&query).await.unwrap().collect().await.unwrap());

        // find task with tgid == pid, offcpu >= 2 * sleep_after_lock and futex_wait in stacks
        let parent = rst.iter().find(|item| {
            item.tgid == item.pid
                && item.offcpu >= 2 * self.sleep_after_lock
                && item.stacks().any(|stack| stack.contains("futex_wait"))
        });
        assert!(
            parent.is_some(),
            "parent events always should wait for 2 sleep durations for child threads"
        );
        // find two tasks that wait in nanosleep for ~ sleep duration
        let nanosleeps = rst
            .iter()
            .filter(|item| {
                item.tgid != item.pid
                    && item.stacks().any(|stack| stack.contains("nanosleep"))
                    && item.offcpu >= self.sleep_after_lock
            })
            .count();
        assert_eq!(nanosleeps, 2, "two threads should wait in nanosleep for sleep duration");
        // find 3 tasks with do_exit stack and 0 offcpu
        let exits = rst
            .iter()
            .filter(|item| {
                item.stacks().any(|stack| stack.contains("do_exit")) && item.offcpu == Duration::from_nanos(0)
            })
            .count();
        assert_eq!(exits, 3, "three threads should exit");
    }
}

struct OffcpuData {
    tgid: u32,
    pid: u32,
    offcpu: Duration,
    kstack: Option<Arc<dyn Array>>,
}

impl OffcpuData {
    fn stacks(&self) -> impl Iterator<Item = &str> + '_ {
        self.kstack.as_ref().unwrap().as_string::<i32>().iter().flatten()
    }
}

struct OffcpuDataFrame(Vec<RecordBatch>);

impl OffcpuDataFrame {
    fn iter(&self) -> impl Iterator<Item = OffcpuData> + '_ {
        self.0.iter().flat_map(|batch| {
            let tgid = batch.column(0).as_primitive::<Int32Type>();
            let pid = batch.column(1).as_primitive::<Int32Type>();
            let offcpu = batch.column(2).as_primitive::<Int64Type>();
            let kstacks = batch.column(3).as_any().downcast_ref::<ListArray>().unwrap();
            multizip((tgid.iter(), pid.iter(), offcpu.iter(), kstacks.iter())).map(|(tgid, pid, offcpu, kstacks)| {
                OffcpuData {
                    tgid: tgid.unwrap_or(0) as u32,
                    pid: pid.unwrap_or(0) as u32,
                    offcpu: Duration::from_nanos(offcpu.unwrap_or(0) as u64),
                    kstack: kstacks,
                }
            })
        })
    }
}

#[derive(Debug, Clone)]
enum Op {
    // Run a testable
    Run(Process),
    // Wait for all testables to finish if test reached the limit of concurrent programs
    Wait,
}

#[derive(Debug, Clone)]
enum Testable {
    #[allow(dead_code)]
    Sleeper(Sleeper),
    Locker(Locker),
}

#[derive(Debug, Clone)]
struct Process {
    virtual_id: u32,
    testable: Testable,
}

#[derive(Debug, Clone)]
struct RefSystemState {
    max_running: usize,
    completed: Vec<Process>,
    running: Vec<Process>,
}

#[derive(Debug)]
struct RefSystem;

impl ReferenceStateMachine for RefSystem {
    type State = RefSystemState;
    type Transition = Op;

    fn init_state() -> BoxedStrategy<Self::State> {
        (5..10usize)
            .prop_map(|max_running| RefSystemState {
                completed: vec![],
                max_running,
                running: vec![],
            })
            .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        assert!(state.running.len() <= state.max_running);
        if state.running.len() == state.max_running {
            return Just(Op::Wait).boxed();
        }
        let virtual_id = state.completed.len() as u32 + state.running.len() as u32;
        let locker = (10..100u64).prop_map(move |millis| {
            let locker = Locker::new(Duration::from_millis(millis));
            Op::Run(Process {
                virtual_id,
                testable: Testable::Locker(locker),
            })
        });
        prop_oneof![
            1 => Just(Op::Wait),
            9 => prop_oneof![locker],
        ]
        .boxed()
    }

    fn apply(mut state: Self::State, op: &Self::Transition) -> Self::State {
        match op {
            Op::Wait => {
                state.completed.append(&mut state.running);
            }
            Op::Run(process) => {
                state.running.push(process.clone());
            }
        }
        state
    }
}

#[derive(Debug)]
struct System;

#[derive(Debug)]
struct SystemState {
    tempdir: tempfile::TempDir,
    tracer_process: Option<Child>,
    virtual_to_tgid: HashMap<u32, u32>,
    running: HashMap<u32, Child>,
}

impl SystemState {
    fn new() -> Self {
        let tempdir = TempDir::with_prefix("e2etrace-test").unwrap();
        let tracer_process = Command::new(&CONFIG.past_binary)
            .arg("--dir")
            .arg(tempdir.path())
            .arg("--poll")
            .arg("100ms")
            .arg("--rows")
            .arg("5000")
            .arg("--groups-per-file")
            .arg("1")
            .arg(Sleeper::expected_comm())
            .arg(Locker::expected_comm())
            .spawn()
            .expect("failed to spawn process");
        Self {
            tempdir,
            tracer_process: Some(tracer_process),
            virtual_to_tgid: HashMap::new(),
            running: HashMap::new(),
        }
    }
}

impl StateMachineTest for System {
    type SystemUnderTest = SystemState;
    type Reference = RefSystem;

    fn init_test(_ref_state: &<Self::Reference as ReferenceStateMachine>::State) -> Self::SystemUnderTest {
        SystemState::new()
    }

    fn apply(
        mut sut: Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        match transition {
            Op::Run(Process {
                virtual_id,
                testable: Testable::Locker(locker),
            }) => {
                let child = locker.spawn();
                sut.virtual_to_tgid.insert(virtual_id, child.id());
                sut.running.insert(child.id(), child);
            }
            Op::Run(Process {
                virtual_id,
                testable: Testable::Sleeper(sleeper),
            }) => {
                let child = sleeper.spawn();
                sut.virtual_to_tgid.insert(virtual_id, child.id());
                sut.running.insert(child.id(), child);
            }
            Op::Wait => {
                // wait for all running processes to finish
                for (_, child) in sut.running.drain() {
                    let status = child.wait_with_output().expect("failed to wait for child");
                    assert!(
                        status.status.success(),
                        "STDOUT: {:?}\nSTDERR: {:?}",
                        status.stdout,
                        status.stderr,
                    );
                }
            }
        }
        sut
    }

    // check_invariants are executed after tracer completed
    fn check_invariants(state: &Self::SystemUnderTest, ref_state: &<Self::Reference as ReferenceStateMachine>::State) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ctx = SessionContext::new();
            let files = state
                .tempdir
                .path()
                .read_dir()
                .expect("failed to read dir")
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            debug!(
                "reading stacks from {}. files {:?}",
                state.tempdir.path().to_str().unwrap(),
                files,
            );
            ctx.register_listing_table(
                "stacks",
                format!("{}/STACKS-*.parquet", state.tempdir.path().to_str().unwrap()),
                ListingOptions::new(Arc::new(ParquetFormat::default()))
                    .with_file_extension(FileType::PARQUET.get_ext()),
                None,
                None,
            )
            .await
            .expect("failed to register stacks table");

            for completed in &ref_state.completed {
                let tgid = state.virtual_to_tgid[&completed.virtual_id];
                match &completed.testable {
                    Testable::Locker(locker) => {
                        locker.verify(&ctx, tgid).await;
                    }
                    Testable::Sleeper(sleeper) => {
                        sleeper.verify(&ctx, tgid).await;
                    }
                }
            }
        });
    }

    fn test_sequential(
        _config: ProptestConfig,
        mut ref_state: <Self::Reference as ReferenceStateMachine>::State,
        transitions: Vec<Op>,
        seen_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) {
        let mut sut = Self::init_test(&ref_state);
        // i can also poll bpf for maps/progs existence in order to check when programs are loaded
        sleep(Duration::from_secs(1));
        for transition in transitions {
            debug!("applying transition: {:?}", transition);
            ref_state = Self::Reference::apply(ref_state, &transition);
            sut = Self::apply(sut, &ref_state, transition);
            if let Some(seen_counter) = seen_counter.as_ref() {
                seen_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        // let tracer collect data in buffers
        sleep(Duration::from_secs(1));
        let tracer = sut.tracer_process.take().unwrap();
        let rst = signal::kill(Pid::from_raw(tracer.id() as i32), signal::Signal::SIGINT);
        assert!(rst.is_ok());
        let out = tracer.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "STDOUT: {:?}\nSTDERR: {:?}",
            out.stdout,
            out.stderr
        );
        Self::check_invariants(&sut, &ref_state);
    }
}
