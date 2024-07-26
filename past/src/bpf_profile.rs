use std::{
    mem::size_of_val,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
};

use libbpf_rs::{
    self,
    libbpf_sys::{bpf_enable_stats, bpf_obj_get_info_by_fd, bpf_prog_info, BPF_STATS_RUN_TIME},
    Program, Result,
};

pub(crate) fn enable() -> Result<StatsFd> {
    let fd = unsafe { bpf_enable_stats(BPF_STATS_RUN_TIME) };
    if fd < 0 {
        Err(libbpf_rs::Error::from_raw_os_error(fd))
    } else {
        Ok(StatsFd {
            _fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }
}

#[derive(Debug)]
pub(crate) struct Stats {
    pub(crate) name: String,
    pub(crate) runtime_ns: u64,
    pub(crate) runtime_cnt: u64,
}

#[derive(Debug)]
pub(crate) struct StatsFd {
    _fd: OwnedFd,
}

impl StatsFd {
    pub(crate) fn get_stats(&self, prog: &Program) -> Result<Stats> {
        let mut item = bpf_prog_info::default();
        let item_ptr: *mut bpf_prog_info = &mut item;
        let mut len = size_of_val(&item) as u32;
        let rst = unsafe { bpf_obj_get_info_by_fd(prog.as_fd().as_raw_fd(), item_ptr as *mut c_void, &mut len) };
        if rst < 0 {
            return Err(libbpf_rs::Error::from_raw_os_error(rst));
        }
        Ok(Stats {
            name: null_terminated_to_string(&item.name),
            runtime_ns: item.run_time_ns,
            runtime_cnt: item.run_cnt,
        })
    }
}

fn null_terminated_to_string(name: &[i8; 16]) -> String {
    let name = match name.iter().position(|&b| b == 0) {
        Some(pos) => &name[..pos],
        None => name,
    };
    String::from_utf8(name.iter().copied().map(|b| b as u8).collect()).unwrap()
}
