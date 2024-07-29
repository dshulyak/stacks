use std::{fmt::Display, mem::MaybeUninit, path::PathBuf, str::Split};

use anyhow::{Context, Result};
use libbpf_rs::{
    libbpf_sys::{PERF_COUNT_SW_CPU_CLOCK, PERF_TYPE_SOFTWARE},
    skel::{OpenSkel, SkelBuilder},
    Link,
};

use crate::{
    perf_event::{attach_perf_event, perf_event_per_cpu},
    PastSkel, PastSkelBuilder,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProgramName {
    Profile,
    Rss,
    Switch,
    Exit,
    Exec,
    TraceEnter,
    TraceExit,
    TraceClose,
    Block,
}

impl From<ProgramName> for &'static str {
    fn from(name: ProgramName) -> &'static str {
        match name {
            ProgramName::Profile => "profile",
            ProgramName::Rss => "rss",
            ProgramName::Switch => "switch",
            ProgramName::Exit => "exit",
            ProgramName::Exec => "exec",
            ProgramName::TraceEnter => "trace_enter",
            ProgramName::TraceExit => "trace_exit",
            ProgramName::TraceClose => "trace_close",
            ProgramName::Block => "block",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Program {
    Profile(Profile),
    Rss(Rss),
    Switch(Switch),
    Block(Block),
}

impl Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Program::Profile(profile) => write!(f, "{}", profile),
            Program::Rss(rss) => write!(f, "{}", rss),
            Program::Switch(switch) => write!(f, "{}", switch),
            Program::Block(block) => write!(f, "{}", block),
        }
    }
}

impl TryFrom<&str> for Program {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let mut parts = value.split(':');
        match parts.next() {
            Some("profile") => Ok(Program::Profile(parts.try_into()?)),
            Some("rss") => Ok(Program::Rss(parts.try_into()?)),
            Some("switch") => Ok(Program::Switch(parts.try_into()?)),
            Some("block") => Ok(Program::Block(parts.try_into()?)),
            Some(program) => anyhow::bail!("invalid program {}", program),
            None => anyhow::bail!("empty program"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Programs {
    profile: Option<Profile>,
    rss: Option<Rss>,
    switch: Option<Switch>,
    block: Option<Block>,
}

impl Display for Programs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut programs = vec![];
        if let Some(profile) = &self.profile {
            programs.push(format!("{}", profile));
        }
        if let Some(rss) = &self.rss {
            programs.push(format!("{}", rss));
        }
        if let Some(switch) = &self.switch {
            programs.push(format!("{}", switch));
        }
        if let Some(block) = &self.block {
            programs.push(format!("{}", block));
        }
        write!(f, "{}", programs.join(", "))
    }
}

impl Programs {
    pub(crate) fn new() -> Self {
        Programs {
            profile: None,
            rss: None,
            switch: None,
            block: None,
        }
    }

    pub(crate) fn profile_frequency(&self) -> u64 {
        self.profile.as_ref().map_or(1, |p| p.frequency)
    }

    pub(crate) fn try_from_programs(progs: impl Iterator<Item = Program>) -> Result<Self> {
        let mut programs = Programs::new();
        for program in progs {
            // raise an error if the program is already set
            match program {
                Program::Profile(profile) => {
                    if programs.profile.is_some() {
                        anyhow::bail!("duplicate profile. {} and {}", programs.profile.unwrap(), profile);
                    }
                    programs.profile = Some(profile);
                }
                Program::Rss(rss) => {
                    if programs.rss.is_some() {
                        anyhow::bail!("duplicat rss. {} and {}", programs.rss.unwrap(), rss);
                    }
                    programs.rss = Some(rss);
                }
                Program::Switch(switch) => {
                    if programs.switch.is_some() {
                        anyhow::bail!("duplicate switch. {} and {}", programs.switch.unwrap(), switch);
                    }
                    programs.switch = Some(switch);
                }
                Program::Block(block) => {
                    if programs.block.is_some() {
                        anyhow::bail!("duplicate block. {} and {}", programs.block.unwrap(), block);
                    }
                    programs.block = Some(block);
                }
            }
        }
        Ok(programs)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Switch {
    stacks: Stacks,
    minimal_span_duration: u64,
}

impl Display for Switch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "switch:{}:{}",
            self.stacks,
            humantime::format_duration(std::time::Duration::from_nanos(self.minimal_span_duration))
        )
    }
}

impl<'a> TryFrom<Split<'a, char>> for Switch {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut switch = Switch::default();
        for item in value {
            let maybe_stacks: Result<Stacks> = item.try_into();
            let maybe_duration = humantime::parse_duration(item);
            match (maybe_stacks, maybe_duration) {
                (Ok(stacks), Err(_)) => {
                    switch.stacks = stacks;
                }
                (Err(_), Ok(duration)) => {
                    switch.minimal_span_duration = duration.as_nanos() as u64;
                }
                (Err(_), Err(_)) => anyhow::bail!("invalid configuration item for switch {}", item),
                (Ok(stacks), Ok(duration)) => {
                    switch.minimal_span_duration = duration.as_nanos() as u64;
                    switch.stacks = stacks;
                }
            }
        }
        Ok(switch)
    }
}

impl Default for Switch {
    fn default() -> Self {
        Switch {
            stacks: Stacks::K,
            minimal_span_duration: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Profile {
    stacks: Stacks,
    frequency: u64,
}

impl Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile:{}:{}", self.stacks, self.frequency)
    }
}

impl<'a> TryFrom<Split<'a, char>> for Profile {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut profile = Profile::default();
        for item in value.take(2) {
            let maybe_stacks: Result<Stacks> = item.try_into();
            let maybe_frequency = item.parse::<u64>();
            match (maybe_stacks, maybe_frequency) {
                (Ok(stacks), Err(_)) => {
                    profile.stacks = stacks;
                }
                (Err(_), Ok(frequency)) => {
                    profile.frequency = frequency;
                }
                (Err(_), Err(_)) => anyhow::bail!("invalid configuration item for profile {}", item),
                (Ok(stacks), Ok(frequncy)) => {
                    // this is impossible but also not incorrect
                    profile.stacks = stacks;
                    profile.frequency = frequncy;
                }
            }
        }
        Ok(profile)
    }
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            stacks: Stacks::U,
            frequency: 99,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Block {
    stacks: Stacks,
}

impl Default for Block {
    fn default() -> Self {
        Block { stacks: Stacks::N }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block:{}", self.stacks)
    }
}

impl<'a> TryFrom<Split<'a, char>> for Block {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut block = Block::default();
        for item in value {
            let maybe_stacks: Result<Stacks> = item.try_into();
            match maybe_stacks {
                Ok(stacks) => {
                    block.stacks = stacks;
                }
                Err(_) => anyhow::bail!("invalid configuration item for block {}", item),
            }
        }
        Ok(block)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Rss {
    stacks: Stacks,
    throttle: u16,
}

impl Display for Rss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rss:{}:{}", self.stacks, self.throttle)
    }
}

impl<'a> TryFrom<Split<'a, char>> for Rss {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut rss = Rss::default();
        for item in value.take(2) {
            let maybe_stacks: Result<Stacks> = item.try_into();
            let maybe_throttle = item.parse::<u16>();
            match (maybe_stacks, maybe_throttle) {
                (Ok(stacks), Err(_)) => {
                    rss.stacks = stacks;
                }
                (Err(_), Ok(throttle)) => {
                    rss.throttle = throttle;
                }
                (Err(_), Err(_)) => anyhow::bail!(
                    "invalid {}. correct syntax is rss:<stacks>:<throttle>, such as rss:ku:16",
                    item
                ),
                (Ok(stacks), Ok(throttle)) => {
                    // this is impossible but also not incorrect
                    rss.stacks = stacks;
                    rss.throttle = throttle;
                }
            }
        }
        Ok(rss)
    }
}

impl Default for Rss {
    fn default() -> Self {
        Rss {
            stacks: Stacks::U,
            throttle: 29,
        }
    }
}

#[derive(Debug, Clone)]
enum Stacks {
    U,
    K,
    UK,
    KU,
    N,
}

impl TryFrom<&str> for Stacks {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "u" => Ok(Stacks::U),
            "k" => Ok(Stacks::K),
            "uk" => Ok(Stacks::UK),
            "ku" => Ok(Stacks::KU),
            "n" => Ok(Stacks::N),
            _ => anyhow::bail!("invalid stack type {}", value),
        }
    }
}

impl Display for Stacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stacks::U => write!(f, "u"),
            Stacks::K => write!(f, "k"),
            Stacks::UK => write!(f, "uk"),
            Stacks::KU => write!(f, "ku"),
            Stacks::N => write!(f, "n"),
        }
    }
}

fn decode_stack_options_into_bpf_cfg(opts: &Stacks, kstack: &mut MaybeUninit<bool>, ustack: &mut MaybeUninit<bool>) {
    match opts {
        Stacks::U => {
            kstack.write(false);
            ustack.write(true);
        }
        Stacks::K => {
            kstack.write(true);
            ustack.write(false);
        }
        Stacks::UK | Stacks::KU => {
            kstack.write(true);
            ustack.write(true);
        }
        Stacks::N => {
            kstack.write(false);
            ustack.write(false);
        }
    }
}

pub(crate) fn link<'a>(
    programs: &Programs,
    usdt: &'a [PathBuf],
    debug: bool,
    events_max_entries: u32,
    stacks_max_entries: u32,
) -> Result<(PastSkel<'a>, Vec<Link>)> {
    let mut skel = PastSkelBuilder::default().open().context("open skel")?;
    let cfg = &mut skel.rodata_mut().cfg;
    cfg.filter_tgid.write(true);
    cfg.filter_comm.write(true);
    cfg.debug.write(debug);
    // is 20% good enough or better to make it configurable?
    cfg.wakeup_bytes = events_max_entries as u64 * 30 / 100;
    if let Some(Profile { stacks, frequency: _ }) = &programs.profile {
        decode_stack_options_into_bpf_cfg(stacks, &mut cfg.perf_kstack, &mut cfg.perf_ustack);
    }
    if let Some(Rss { stacks, throttle }) = &programs.rss {
        decode_stack_options_into_bpf_cfg(stacks, &mut cfg.rss_kstack, &mut cfg.rss_ustack);
        cfg.rss_stat_throttle = *throttle;
    }
    if let Some(Switch {
        stacks,
        minimal_span_duration,
    }) = &programs.switch
    {
        decode_stack_options_into_bpf_cfg(stacks, &mut cfg.switch_kstack, &mut cfg.switch_ustack);
        cfg.minimal_switch_duration = *minimal_span_duration;
    }
    if let Some(Block { stacks }) = &programs.block {
        decode_stack_options_into_bpf_cfg(stacks, &mut cfg.blk_kstack, &mut cfg.blk_ustack);
    }
    skel.maps_mut()
        .events()
        .set_max_entries(events_max_entries)
        .context("set events max entries")?;

    skel.maps_mut()
        .stackmap()
        .set_max_entries(stacks_max_entries)
        .context("set stackmap max entries")?;

    let mut skel = skel.load().context("load skel")?;
    let mut links = vec![];

    if let Some(profile) = &programs.profile {
        let perf_fds = perf_event_per_cpu(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, profile.frequency)
            .context("init perf events")?;
        links.extend(attach_perf_event(&perf_fds, skel.progs_mut().handle__perf_event())?);
    }
    if programs.rss.is_some() {
        links.push(
            skel.progs_mut()
                .handle__mm_trace_rss_stat()
                .attach()
                .context("attach mm_trace_rss_stat")?,
        );
    }
    if programs.switch.is_some() {
        links.push(
            skel.progs_mut()
                .handle__sched_switch()
                .attach()
                .context("attach sched_switch")?,
        );
    }
    if programs.block.is_some() {
        links.push(
            skel.progs_mut()
                .block_io_start()
                .attach()
                .context("attach block io start")?,
        );
        links.push(
            skel.progs_mut()
                .block_io_done()
                .attach()
                .context("attach block io end")?,
        );
    }
    links.push(
        skel.progs_mut()
            .handle__sched_process_exit()
            .attach()
            .context("attach sched exit")?,
    );
    links.push(
        skel.progs_mut()
            .handle__sched_process_exec()
            .attach()
            .context("attach sched exec")?,
    );

    for u in usdt {
        let _usdt_enter = skel
            .progs_mut()
            .past_tracing_enter()
            .attach_usdt(-1, u, "past_tracing", "enter")
            .context("usdt enter")?;
        let _usdt_exit = skel
            .progs_mut()
            .past_tracing_exit()
            .attach_usdt(-1, u, "past_tracing", "exit")
            .context("usdt exit")?;
        let _usdt_exit_stack = skel
            .progs_mut()
            .past_tracing_exit_stack()
            .attach_usdt(-1, u, "past_tracing", "exit_stack")
            .context("exit stack link")?;
        let _usdt_close = skel
            .progs_mut()
            .past_tracing_close()
            .attach_usdt(-1, u, "past_tracing", "close")
            .context("usdt close")?;
        links.push(_usdt_enter);
        links.push(_usdt_exit);
        links.push(_usdt_exit_stack);
        links.push(_usdt_close);
    }

    Ok((skel, links))
}
