use std::{
    collections::{hash_map, HashMap, HashSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{debug, info, warn};

use crate::{
    collector::{null_terminated, symbolize, Collector, Frames, Received, Symbolizer},
    parquet::{Compression, Group, GroupWriter},
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

pub(crate) struct State<Fr: Frames, Sym: Symbolizer> {
    cfg: Config,
    writer: Option<GroupWriter<File>>,
    collector: Collector,
    frames: Fr,
    symbolizer: Sym,
    // cleanup should occur after frames from last batch were collected
    symbolizer_tgid_cleanup: HashSet<u32>,
    tgid_to_command: HashMap<u32, ProcessInfo>,
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
        let pg_size = page_size()?;
        let collector = Collector::new(group, pg_size, cfg.timestamp_adjustment, cfg.perf_event_frequency);
        Ok(State {
            cfg,
            writer: Some(writer),
            collector,
            frames,
            symbolizer,
            symbolizer_tgid_cleanup: HashSet::new(),
            tgid_to_command: HashMap::new(),
            stats,
        })
    }

    pub(crate) fn drop_known_state(&mut self) -> Result<()> {
        for tgid in self.tgid_to_command.keys() {
            self.symbolizer.drop_symbolizer(*tgid)?;
        }
        self.collector.drop_known_spans();
        self.tgid_to_command.clear();
        self.symbolizer_tgid_cleanup.clear();
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
                match self.tgid_to_command.entry(event.tgid) {
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

        if let Err(err) = self.collector.collect(&self.tgid_to_command, event) {
            warn!("failed to collect event: {:?}", err);
        }
        if self.collector.group.is_full() {
            debug!("group is full, symbolizing and flushing");
            symbolize(&self.symbolizer, &self.frames, &mut self.collector.group);
            self.writer
                .as_mut()
                .expect("writer must exist")
                .write(self.collector.group.for_writing())?;
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
            on_exit(writer, &mut self.collector.group, &self.symbolizer, &self.frames).context("closing last file")?;
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
