use std::{
    collections::HashMap,
    fmt::Display,
    mem::size_of_val,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    time,
};

use libbpf_rs::{
    self,
    libbpf_sys::{bpf_enable_stats, bpf_obj_get_info_by_fd, bpf_prog_info, BPF_STATS_RUN_TIME},
    Program, Result,
};
use tracing::info;

use crate::{bpf::ProgramName, StacksProgs};

fn enable() -> Result<StatsFd> {
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
struct StatsFd {
    _fd: OwnedFd,
}

impl StatsFd {
    // get_stats returns the runtime and run count of the program.
    fn get_stats(&self, prog: &Program) -> Result<(u64, u64)> {
        let mut item = bpf_prog_info::default();
        let item_ptr: *mut bpf_prog_info = &mut item;
        let mut len = size_of_val(&item) as u32;
        let rst = unsafe { bpf_obj_get_info_by_fd(prog.as_fd().as_raw_fd(), item_ptr as *mut c_void, &mut len) };
        if rst < 0 {
            return Err(libbpf_rs::Error::from_raw_os_error(rst));
        }
        Ok((item.run_time_ns, item.run_cnt))
    }
}

#[derive(Debug)]
struct DeltaStats {
    program: ProgramName,
    // duration is a wallclock time between two collection.
    // it will be usually configured to something like 10s or 10m.
    duration: time::Duration,
    // runtime_ns is a total runtime of the bpf program.
    runtime_ns: u64,
    // runtime_cnt is a number of events observed by bpf program.
    runtime_cnt: u64,
    // collected_cnt is a number of events collected after filtering.
    // additionally there is a delay between the timepoint when they are observed and collected.
    collected_cnt: u64,
}

impl Display for DeltaStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duration = humantime::Duration::from(self.duration);
        let runtime = humantime::Duration::from(time::Duration::from_nanos(self.runtime_ns));
        let busy = (self.runtime_ns as f64 / self.duration.as_nanos() as f64) * 100.0;
        let collected_latency = self.runtime_ns as f64 / self.collected_cnt as f64;
        let program: &str = self.program.into();
        writeln!(
            f,
            "{:<15} | {:<15.4} | {:<15.4} | {:<15.2} | {:<15} | {:<15} | {:<15.2}",
            program,
            duration.as_secs_f64(),
            runtime.as_secs_f64(),
            busy,
            self.runtime_cnt,
            self.collected_cnt,
            collected_latency
        )
    }
}

struct MultiLineStats<'a>(&'a [DeltaStats]);

impl Display for MultiLineStats<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "{:<15} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15}",
            "program", "duration s", "runtime s", "busy %", "runtime cnt", "collected cnt", "collected latency ns"
        )?;
        for stat in self.0 {
            stat.fmt(f)?;
        }
        Ok(())
    }
}

pub(crate) struct ProgramStats {
    runtime_ns: u64,
    runtime_cnt: u64,
    collected_cnt: u64,
}

pub(crate) struct Profiler {
    fd: StatsFd,
    interval: time::Duration,
    last: time::Instant,
    stats: HashMap<ProgramName, ProgramStats>,
    events_per_program_counter: HashMap<ProgramName, u64>,
    scratch: Vec<DeltaStats>,
}

impl Profiler {
    pub(crate) fn enable(interval: time::Duration) -> Result<Self> {
        Ok(Profiler {
            fd: enable()?,
            last: time::Instant::now(),
            interval,
            stats: HashMap::new(),
            events_per_program_counter: HashMap::new(),
            scratch: vec![],
        })
    }

    pub(crate) fn collect(&mut self, name: ProgramName) {
        let counter = self.events_per_program_counter.entry(name).or_insert(0);
        *counter += 1;
    }

    pub(crate) fn log_stats(&mut self, progs: &StacksProgs) -> Result<()> {
        let ts: time::Instant = time::Instant::now();
        for (name, collected_cnt) in self.events_per_program_counter.iter() {
            let (runtime_ns, runtime_cnt) = collect_stats_for_program(*name, progs, &self.fd)?;
            let previous = self.stats.entry(*name).or_insert(ProgramStats {
                runtime_ns: 0,
                runtime_cnt: 0,
                collected_cnt: 0,
            });

            let delta = DeltaStats {
                program: *name,
                duration: ts.duration_since(self.last),
                runtime_ns: runtime_ns - previous.runtime_ns,
                runtime_cnt: runtime_cnt - previous.runtime_cnt,
                collected_cnt: collected_cnt - previous.collected_cnt,
            };

            previous.runtime_ns = runtime_ns;
            previous.runtime_cnt = runtime_cnt;
            previous.collected_cnt = *collected_cnt;

            self.scratch.push(delta);
        }
        self.last = ts;
        if !self.scratch.is_empty() {
            info!("BPF PROFILE:\n{}", MultiLineStats(self.scratch.as_slice()));
            self.scratch.clear();
        }
        Ok(())
    }

    pub(crate) fn log_stats_on_interval(&mut self, progs: &StacksProgs) -> Result<()> {
        let ts: time::Instant = time::Instant::now();
        if ts.duration_since(self.last) < self.interval {
            return Ok(());
        }
        self.log_stats(progs)
    }
}

fn collect_stats_for_program<'a>(name: ProgramName, progs: &'a StacksProgs<'a>, fd: &StatsFd) -> Result<(u64, u64)> {
    match name {
        ProgramName::Profile => fd.get_stats(progs.handle__perf_event()),
        ProgramName::Rss => fd.get_stats(progs.handle__mm_trace_rss_stat()),
        ProgramName::Switch => fd.get_stats(progs.handle__sched_switch()),
        ProgramName::Exit => fd.get_stats(progs.handle__sched_process_exit()),
        ProgramName::Exec => fd.get_stats(progs.handle__sched_process_exec()),
        ProgramName::TraceEnter => fd.get_stats(progs.stacks_tracing_enter()),
        ProgramName::TraceExit => fd.get_stats(progs.stacks_tracing_exit()),
        ProgramName::TraceClose => fd.get_stats(progs.stacks_tracing_close()),
        ProgramName::Block => {
            let (start_ns, start_cnt) = fd.get_stats(progs.block_io_start())?;
            let (done_ns, done_cnt) = fd.get_stats(progs.block_io_done())?;
            Ok((start_ns + done_ns, start_cnt + done_cnt))
        }
        ProgramName::Vfs => {
            let (read_ns, read_cnt) = fd.get_stats(progs.vfs_read())?;
            let (readv_ns, readv_cnt) = fd.get_stats(progs.vfs_readv())?;
            let (write_ns, write_cnt) = fd.get_stats(progs.vfs_write())?;
            let (writev_ns, writev_cnt) = fd.get_stats(progs.vfs_writev())?;
            Ok((
                read_ns + readv_ns + write_ns + writev_ns,
                read_cnt + readv_cnt + write_cnt + writev_cnt,
            ))
        }
        ProgramName::Net => {
            let (udp_recv_ns, udp_recv_cnt) = fd.get_stats(progs.udp_recvmsg())?;
            let (udp_send_ns, udp_send_cnt) = fd.get_stats(progs.udp_sendmsg())?;
            let (tcp_recv_ns, tcp_recv_cnt) = fd.get_stats(progs.tcp_recvmsg())?;
            let (tcp_send_ns, tcp_send_cnt) = fd.get_stats(progs.tcp_sendmsg())?;
            Ok((
                udp_recv_ns + udp_send_ns + tcp_recv_ns + tcp_send_ns,
                udp_recv_cnt + udp_send_cnt + tcp_recv_cnt + tcp_send_cnt,
            ))
        }
    }
}
