use std::{
    fs::{self, File},
    path::Path,
    time::SystemTime,
};

use anyhow::{Context, Result};
use crossbeam::channel::Receiver;

use crate::{
    parquet::{Group, GroupWriter},
    state::Config,
    symbolizer::symbolize,
    Frames, Symbolizer,
};

// parquet file is invalid until footer is written.
// writing to a file with different prefix allows to register only valid files without stopping the program.
// also if program crashes it is much more desirable to avoid manual recovery by deleting unfinished file.
const PENDING_FILE_PREFIX: &str = "PENDING";
const FILE_PREFIX: &str = "STACKS";

pub(crate) struct GroupWriteRequest {
    group: Group,
    exited_tgids: Vec<u32>
}

impl GroupWriteRequest {
    pub fn new(group: Group, exited_tgids: Vec<u32>) -> Self {
        Self { group, exited_tgids }
    }
}

pub(crate) fn persist_groups(
    cfg: Config,
    frames: impl Frames,
    mut symbolizer: impl Symbolizer,
    receiver: Receiver<GroupWriteRequest>,
) -> Result<()> {
    let mut writer = GroupWriter::with_compression(
        create_file(&cfg.directory, PENDING_FILE_PREFIX).context("creating pending file")?,
        cfg.compression,
    )?;
    let mut groups_in_file = 0;
    let mut current_index = 0;
    for mut group in receiver {
        groups_in_file += 1;
        symbolize(&symbolizer, &frames, &mut group.group);
        for exited in group.exited_tgids {
            symbolizer.drop_symbolizer(exited);
        }
        writer.write(group.group.for_writing())?;
        if cfg.groups_per_file == groups_in_file {
            move_file_with_timestamp(&cfg.directory, PENDING_FILE_PREFIX, FILE_PREFIX, current_index)?;
            current_index += 1;
            groups_in_file = 0;
            writer.close()?;
            writer = GroupWriter::with_compression(
                create_file(&cfg.directory, PENDING_FILE_PREFIX).context("creating pending file")?,
                cfg.compression,
            )?;
        }
    }
    // the last group is already written we just move it from pending to stable
    // but in case if it was actually last group for the file, there is nothing left to do
    if groups_in_file != 0 {
        move_file_with_timestamp(&cfg.directory, PENDING_FILE_PREFIX, FILE_PREFIX, current_index)?;
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
