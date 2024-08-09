use std::{
    fmt::{self, Display, Formatter},
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    time::{self, Instant},
};

use datafusion::{
    arrow::array::{Array, ArrowNativeTypeOp, AsArray, Int64Array, ListArray, RecordBatch, StringArray, UInt64Array},
    common::{FileType, GetExt},
    datasource::{file_format::parquet::ParquetFormat, listing::ListingOptions},
    execution::context::SessionContext,
};
use once_cell::sync::Lazy;
use serial_test::serial;
use tempfile::tempdir;
use tracing::{error, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

static STACKS_BINARY: Lazy<PathBuf> = Lazy::new(|| {
    if let Ok(path) = std::env::var("STACKS_BINARY") {
        PathBuf::from(path)
    } else {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../target/debug/stacks");
        path
    }
});

static EXAMPLES_DIRECTORY: Lazy<PathBuf> = Lazy::new(|| {
    if let Ok(path) = std::env::var("EXAMPLES_DIRECTORY") {
        PathBuf::from(path)
    } else {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../target/debug/examples");
        path
    }
});

const LOCK_BINARY: &str = "lock";
const SLEEP_BINARY: &str = "sleep";
const WRITER_BINARY: &str = "writer";
const RSS_BINARY: &str = "rss";
const PINGPONG_BINARY: &str = "pingpong_sync";
const PINGPONG_ASYNC_BINARY: &str = "pingpong_async";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .try_init();
}

#[derive(Debug)]
struct CommandArgs {
    binary: PathBuf,
    args: Vec<String>,
}

impl Display for CommandArgs {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.binary.display())?;
        for arg in &self.args {
            write!(f, " {}", arg)?;
        }
        Ok(())
    }
}

fn run(args: CommandArgs) -> Child {
    let mut command = Command::new(&args.binary);
    for value in args.args.iter() {
        command.arg(value);
    }
    match command.spawn() {
        Ok(child) => child,
        Err(err) => panic!("failed to start {}: {}", args, err),
    }
}

// wait_kill waits for child process to finish and kills it if it didn't finish within duration
fn wait_kill(mut child: Child, duration: time::Duration) {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed() > duration {
                    if let Err(err) = child.kill() {
                        error!("kill: {}", err);
                    }
                } else {
                    std::thread::sleep(time::Duration::from_millis(10));
                }
            }
            Err(e) => {
                error!("wait: {}", e);
                return;
            }
        }
    }
}

fn interrupt(child: &Child) -> Result<(), std::io::Error> {
    unsafe {
        if libc::kill(child.id() as i32, libc::SIGINT) != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn interrupt_and_wait(child: Child, duration: time::Duration) {
    if let Err(err) = interrupt(&child) {
        error!("terminate: {}", err);
    }
    wait_kill(child, duration)
}

fn stacks_args(tmpdir: &Path, rows_per_file: u64) -> CommandArgs {
    CommandArgs {
        binary: STACKS_BINARY.clone(),
        args: vec![
            LOCK_BINARY.to_string(),
            SLEEP_BINARY.to_string(),
            RSS_BINARY.to_string(),
            WRITER_BINARY.to_string(),
            PINGPONG_BINARY.to_string(),
            PINGPONG_ASYNC_BINARY.to_string(),
            format!("--dir={}", tmpdir.display()),
            format!("--rows={}", rows_per_file),
            format!("--groups-per-file=1"),
            format!("-p=profile:ku,switch:ku,rss:ku:1,block:ku,vfs:ku,net:ku"),
        ],
    }
}

// poll_stacks_init waits for stacks binary to start up and initialize bpf programs
// by watching it create any file in temp directory.
//
// if it doesn't startup within specified duration it fails
fn poll_stacks_init(tmpdir: &Path, duration: time::Duration, wait_between_polling: time::Duration) {
    let start = Instant::now();
    while start.elapsed() < duration {
        let entries = tmpdir.read_dir().expect("failed to read dir");
        if entries.count() > 0 {
            return;
        }
        std::thread::sleep(wait_between_polling);
    }
    panic!("stacks binary failed to start within {:?}", duration);
}

fn writer_args(tmpdir: &Path, size: u64, chunk: u64, fsync: bool) -> CommandArgs {
    CommandArgs {
        binary: EXAMPLES_DIRECTORY.join(WRITER_BINARY),
        args: vec![
            tmpdir.join("writer").display().to_string(),
            format!("--size={}", size),
            format!("--chunk={}", chunk),
            if fsync { "--fsync".to_string() } else { "".to_string() },
        ],
    }
}

fn lock_args(sleep_ms: u64) -> CommandArgs {
    CommandArgs {
        binary: EXAMPLES_DIRECTORY.join(LOCK_BINARY),
        args: vec![format!("--duration={}", sleep_ms)],
    }
}

#[derive(Debug)]
struct SpanWithStacks {
    start: u64,
    end: u64,
    stacks: Vec<String>,
}

#[derive(Debug)]
struct SpanWithStacksCollection(Vec<SpanWithStacks>);

impl TryFrom<Vec<RecordBatch>> for SpanWithStacksCollection {
    type Error = anyhow::Error;

    fn try_from(batches: Vec<RecordBatch>) -> Result<Self, Self::Error> {
        let mut result = Vec::new();
        for batch in batches {
            let start = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .expect("start column is not u64");
            let end = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .expect("end column is not u64");
            let stacks = batch
                .column(2)
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("stacks be must a list of triples (string, u64, u64)");

            for i in 0..batch.num_rows() {
                let row = stacks.value(i);
                let stacks = row
                    .as_struct()
                    .column_by_name("name")
                    .expect("name column not found")
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .expect("name must be utf8 string")
                    .iter()
                    .filter_map(|name| name.map(|s| s.to_string()))
                    .collect::<Vec<String>>();
                result.push(SpanWithStacks {
                    start: start.value(i),
                    end: end.value(i),
                    stacks,
                });
            }
        }
        Ok(SpanWithStacksCollection(result))
    }
}

#[derive(Debug)]
struct AmountSummary {
    total: u64,
    amount_sum: u64,
}

impl TryFrom<Vec<RecordBatch>> for AmountSummary {
    type Error = anyhow::Error;

    fn try_from(batches: Vec<RecordBatch>) -> Result<Self, Self::Error> {
        let mut total = 0;
        let mut amount_sum = 0;
        for batch in batches {
            let count = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("count column is not i64");
            let amount = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .expect("amount column is not u64");

            for i in 0..batch.num_rows() {
                total += count.value(i) as u64;
                amount_sum += amount.value(i);
            }
        }
        Ok(AmountSummary { total, amount_sum })
    }
}

fn get_data<T: TryFrom<Vec<RecordBatch>>>(dir: &Path, query: &str) -> Result<T, T::Error> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ctx = SessionContext::new();
        ctx.register_listing_table(
            "stacks",
            format!("{}/STACKS-*.parquet", dir.to_str().expect("failed to convert path")),
            ListingOptions::new(Arc::new(ParquetFormat::default())).with_file_extension(FileType::PARQUET.get_ext()),
            None,
            None,
        )
        .await
        .expect("failed to register stacks table");

        let df = ctx
            .sql(query)
            .await
            .expect("failed to execute query")
            .collect()
            .await
            .expect("failed to collect results");
        T::try_from(df)
    })
}

#[test]
#[serial]
fn test_writer() {
    init_tracing();

    let tmpdir = tempdir().expect("failed to create tempdir");
    let size = 200;
    let chunk = 1;
    let stacks = stacks_args(tmpdir.path(), 100);
    let writer = writer_args(tmpdir.path(), size, chunk, true);

    let stacks = run(stacks);
    poll_stacks_init(
        tmpdir.path(),
        time::Duration::from_secs(10),
        time::Duration::from_millis(10),
    );
    let writer = run(writer);
    wait_kill(writer, time::Duration::from_secs(5));
    interrupt_and_wait(stacks, time::Duration::from_secs(5));

    let data = get_data::<AmountSummary>(
        tmpdir.path(),
        r#"
        select count(*), sum(amount) 
        from stacks 
        where command == 'writer' 
              and kind in ('blk_write')
        "#,
    )
    .expect("failed to get data");
    assert_eq!(data.amount_sum, size << 20, "total amount should be equal to {}", size);
    assert!(
        data.amount_sum / data.total <= chunk << 20,
        "blk chunk {} should be no larger then the written amount before fsync {}",
        data.amount_sum / data.total,
        chunk << 20
    );
}

#[test]
#[serial]
fn test_lock() {
    init_tracing();

    let tmpdir = tempdir().expect("failed to create tempdir");
    let sleep_ms = 200;
    let stacks = stacks_args(tmpdir.path(), 100);
    let lock = lock_args(sleep_ms);

    let stacks = run(stacks);
    poll_stacks_init(
        tmpdir.path(),
        time::Duration::from_secs(10),
        time::Duration::from_millis(10),
    );
    let lock = run(lock);
    wait_kill(lock, time::Duration::from_secs(5));
    interrupt_and_wait(stacks, time::Duration::from_secs(5));

    let data = get_data::<SpanWithStacksCollection>(
        tmpdir.path(),
        r#"
        select 
            timestamp, 
            (
                LEAD(timestamp - duration) OVER (
                    PARTITION BY pid
                    ORDER BY
                        timestamp
                )
            ) as wakeup,
            kstack
        from stacks 
        where command == 'lock' and kind in ('switch')
        "#,
    )
    .expect("failed to convert");

    // let sleep =
    let mut do_futex = 0;
    let mut do_nanosleep = 0;
    let do_nanosleep_str = "do_nanosleep".to_string();
    let do_futex_str = "do_futex".to_string();
    for row in data.0 {
        if row.stacks.contains(&do_nanosleep_str) && !row.end.is_zero() {
            do_nanosleep += row.end - row.start;
        }
        if row.stacks.contains(&do_futex_str) && !row.end.is_zero() {
            do_futex += row.end - row.start;
        }
    }
    assert!(
        do_futex >= 200 * 3 * 1_000_000,
        "threads should wait atleast 3 time periods {} in futex.
        1 period second thread that failed to obtain the lock.
        2 period main thread waiting for 2 nanosleeps from child threads.
        ",
        sleep_ms
    );
    assert!(
        do_nanosleep >= 200 * 2 * 1_000_000,
        "threads should wait atleast 2 time periods {} in sleep",
        sleep_ms
    );
}

fn pingpong_sync_args(iters: u64, ping_size: u64, pong_size: u64) -> CommandArgs {
    CommandArgs {
        binary: EXAMPLES_DIRECTORY.join(PINGPONG_BINARY),
        args: vec![
            format!("--ping={}", ping_size),
            format!("--pong={}", pong_size),
            format!("--iters={}", iters),
        ],
    }
}

#[test]
#[serial]
fn test_pingpong_sync() {
    init_tracing();

    let tmpdir = tempdir().expect("failed to create tempdir");
    let stacks = stacks_args(tmpdir.path(), 100);
    let ping_size_kb = 10;
    let pong_size_kb = 20;
    let iters = 10;
    let pingpong = pingpong_sync_args(iters, ping_size_kb, pong_size_kb);

    let stacks = run(stacks);
    poll_stacks_init(
        tmpdir.path(),
        time::Duration::from_secs(10),
        time::Duration::from_millis(10),
    );
    let pingpong = run(pingpong);
    wait_kill(pingpong, time::Duration::from_secs(5));
    interrupt_and_wait(stacks, time::Duration::from_secs(5));

    let sends = get_data::<AmountSummary>(
        tmpdir.path(),
        r#"
        select count(*), sum(amount) 
        from stacks 
        where command == 'pingpong_sync' 
              and kind in ('tcp_send')
        "#,
    )
    .expect("collect sends");
    let recvs = get_data::<AmountSummary>(
        tmpdir.path(),
        r#"
        select count(*), sum(amount) 
        from stacks 
        where command == 'pingpong_sync' 
              and kind in ('tcp_recv')
        "#,
    )
    .expect("collect recvs");

    assert_eq!(sends.total, 2 * iters, "both threads should send 2*iters");
    assert_eq!(recvs.total, 2 * iters, "both threads should recv 2*iters");
    assert_eq!(sends.amount_sum, (ping_size_kb + pong_size_kb) * 1024 * iters);
    assert_eq!(recvs.amount_sum, (ping_size_kb + pong_size_kb) * 1024 * iters);
}

fn rss_args(size_mb: u64) -> CommandArgs {
    CommandArgs {
        binary: EXAMPLES_DIRECTORY.join(RSS_BINARY),
        args: vec![format!("{}", size_mb)],
    }
}

#[test]
#[serial]
fn test_rss() {
    init_tracing();

    let tmpdir = tempdir().expect("failed to create tempdir");
    let stacks = stacks_args(tmpdir.path(), 100);
    let size_mb = 200;
    let size_bytes = 200 << 20;
    let rss = rss_args(size_mb);

    let stacks = run(stacks);
    poll_stacks_init(
        tmpdir.path(),
        time::Duration::from_secs(10),
        time::Duration::from_millis(10),
    );
    let rss = run(rss);
    wait_kill(rss, time::Duration::from_secs(5));
    interrupt_and_wait(stacks, time::Duration::from_secs(5));

    let data = get_data::<AmountSummary>(
        tmpdir.path(),
        r#"
        select count(*), max(amount) 
        from stacks 
        where command == 'rss' 
              and kind in ('rss')
        "#,
    )
    .expect("collect rss");
    let delta = 4 << 20; // 4 MB
    assert!(
        data.amount_sum >= size_bytes && data.amount_sum <= size_bytes + delta,
        "total rss {} should match requested {} within delta {}",
        data.amount_sum,
        size_bytes,
        delta,
    );
}
