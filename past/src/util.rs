use std::{
    collections::{hash_map, HashMap, HashSet},
    fs::{self, File},
    io::Read,
    ops::Deref,
    path::Path,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use bytes::Bytes;
use tracing::debug;

use crate::collector::null_terminated;

pub fn ensure_exists(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

pub fn parse_uptime() -> anyhow::Result<Duration> {
    let mut uptime = String::new();
    fs::File::open("/proc/uptime")?.read_to_string(&mut uptime)?;
    // example format
    // 4039.25                  94816.49
    // seconds.fraction_seconds idle_seconds.fraction_seconds
    // i am only interested in the first part
    let mut parts = uptime.split_whitespace().flat_map(|x| x.split('.'));
    let seconds = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing seconds"))?
        .parse::<u64>()?;
    let fraction_seconds = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing fraction seconds"))?
        .parse::<u64>()?;
    Ok(Duration::from_secs(seconds) + Duration::from_millis(fraction_seconds * 10))
}

#[derive(Debug)]
pub struct Comm([u8; 16]);

impl From<&str> for Comm {
    fn from(s: &str) -> Self {
        let mut comm = [0; 16];
        comm[..s.len()].copy_from_slice(s.as_bytes());
        Self(comm)
    }
}

impl Deref for Comm {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) struct Proc {
    pub(crate) tgid: i32,
    pub(crate) comm: Comm,
}

pub fn scan_proc(comms: HashSet<&str>) -> anyhow::Result<Vec<Proc>> {
    let mut rst = vec![];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Ok(tgid) = name.parse::<u32>() {
            let comm = fs::read_to_string(path.join("comm"))?;
            let trimmed = comm.trim();
            if comms.contains(trimmed) {
                rst.push(Proc {
                    tgid: tgid as i32,
                    comm: Comm::from(trimmed),
                });
                debug!("discovered tgid = {} for command = {}", tgid, comm);
            }
        }
    }
    Ok(rst)
}

pub(crate) fn create_file(dir: &Path, prefix: &str) -> Result<File> {
    Ok(File::create(dir.join(format!("{}.parquet", prefix)))?)
}

pub(crate) fn move_file_with_timestamp(dir: &Path, from_prefix: &str, to_prefix: &str, index: usize) -> Result<()> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    let from = dir.join(format!("{}.parquet", from_prefix));
    let to = dir.join(format!("{}-{}-{}.parquet", to_prefix, index, now));
    fs::rename(from, to)?;
    Ok(())
}

pub(crate) fn exe_name_and_change_time(tgid: u32) -> Result<(String, u64)> {
    let path = format!("/proc/{}/exe", tgid);
    let exe = fs::read_link(path)?;
    let meta = exe.metadata()?;
    let mtime = meta.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    Ok((exe.to_string_lossy().to_string(), mtime))
}

pub(crate) fn command(commands: &mut HashMap<u32, Bytes>, tgid: u32, command: &[u8]) -> Bytes {
    let comm = null_terminated(command);
    let existing = commands.entry(tgid);
    match existing {
        hash_map::Entry::Vacant(vacant) => vacant.insert(Bytes::copy_from_slice(comm)).clone(),
        hash_map::Entry::Occupied(mut occupied) => {
            if occupied.get() != comm {
                occupied.insert(Bytes::copy_from_slice(comm));
            }
            occupied.get().clone()
        }
    }
}
