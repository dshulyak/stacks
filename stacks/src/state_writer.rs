use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use crossbeam::channel::Receiver;

use crate::{
    parquet::{Group, GroupWriter},
    symbolizer::symbolize,
    BlazesymSymbolizer, Compression, Frames,
};

// parquet file is invalid until footer is written.
// writing to a file with different prefix allows to register only valid files without stopping the program.
// also if program crashes it is much more desirable to avoid manual recovery by deleting unfinished file.
const PENDING_FILE_PREFIX: &str = "PENDING";
const FILE_PREFIX: &str = "STACKS";

pub(crate) enum WriterRequest {
    ProcessCreated(u32, PathBuf, u64, Bytes),
    ProcessExited(u32),
    Reset,
    GroupFull(Box<Group>),
}

pub(crate) fn persist(
    directory: PathBuf,
    groups_per_file: usize,
    compression: Compression,
    frames: impl Frames,
    receiver: Receiver<WriterRequest>,
) -> Result<()> {
    let mut symbolizer = BlazesymSymbolizer::new();
    let mut writer = GroupWriter::with_compression(
        create_file(&directory, PENDING_FILE_PREFIX).context("creating pending file")?,
        compression,
    )?;
    let mut groups_in_file = 0;
    let mut current_index = 0;
    // we are tracking which tgids exited since last time group was flushed
    // after symbolizing tgids from this set we can drop symbolizers for them
    let mut exited_tgids = HashSet::new();
    for request in receiver {
        match request {
            WriterRequest::ProcessCreated(tgid, exe, mtime, buildid) => {
                symbolizer.init_symbolizer(tgid, exe, mtime, buildid)?;
            }
            WriterRequest::ProcessExited(tid) => {
                exited_tgids.insert(tid);
            }
            WriterRequest::Reset => {
                symbolizer = BlazesymSymbolizer::new();
            }
            WriterRequest::GroupFull(mut group) => {
                groups_in_file += 1;
                symbolize(&symbolizer, &frames, &mut group);
                for exited in exited_tgids.drain() {
                    symbolizer.drop_symbolizer(exited)?;
                }
                writer.write(group.for_writing())?;
                if groups_per_file == groups_in_file {
                    move_file_with_timestamp(&directory, PENDING_FILE_PREFIX, FILE_PREFIX, current_index)?;
                    current_index += 1;
                    groups_in_file = 0;
                    writer.close()?;
                    writer = GroupWriter::with_compression(
                        create_file(&directory, PENDING_FILE_PREFIX).context("creating pending file")?,
                        compression,
                    )?;
                }
            }
        }
    }
    // the last group is already written we just move it from pending to stable
    // but in case if it was actually last group for the file, there is nothing left to do
    if groups_in_file != 0 {
        move_file_with_timestamp(&directory, PENDING_FILE_PREFIX, FILE_PREFIX, current_index)?;
    }
    Ok(())
}

fn create_file(dir: impl AsRef<Path>, prefix: &str) -> Result<File> {
    Ok(File::create(dir.as_ref().join(format!("{}.parquet", prefix)))?)
}

fn move_file_with_timestamp(dir: impl AsRef<Path>, from_prefix: &str, to_prefix: &str, index: usize) -> Result<()> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    let from = dir.as_ref().join(format!("{}.parquet", from_prefix));
    let to = dir.as_ref().join(format!("{}-{}-{}.parquet", to_prefix, index, now));
    fs::rename(from, to)?;
    Ok(())
}
