use std::{path::PathBuf, str::Split};

use anyhow::Result;

enum Program {
    Profile(Profile),
    Rss(Rss),
    Switch(Switch),
}

impl TryFrom<&str> for Program {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let mut parts = value.split(':');
        match parts.next() {
            Some("profile") => Ok(Program::Profile(parts.try_into()?)),
            Some("rss") => Ok(Program::Rss(parts.try_into()?)),
            Some("switch") => Ok(Program::Switch(parts.try_into()?)),
            Some(program) => anyhow::bail!("invalid program {}", program),
            None => anyhow::bail!("empty program"),
        }
    }
}

pub(crate) struct Programs {
    profile: Option<Profile>,
    rss: Option<Rss>,
    switch: Option<Switch>,
}

impl Programs {
    pub(crate) fn new() -> Self {
        Programs {
            profile: None,
            rss: None,
            switch: None,
        }
    }
}

impl Default for Programs {
    fn default() -> Self {
        Programs {
            profile: Some(Profile::default()),
            rss: Some(Rss::default()),
            switch: Some(Switch::default()),
        }
    }
}

struct Switch {
    stacks: Stacks,
}

impl<'a> TryFrom<Split<'a, char>> for Switch {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut switch = Switch::default();
        for item in value {
            let maybe_stacks: Result<Stacks> = item.try_into();
            match maybe_stacks {
                Ok(stacks) => {
                    switch.stacks = stacks;
                }
                Err(_) => anyhow::bail!("invalid configuration item for switch {}", item),
            }
        }
        Ok(switch)
    }
}

impl Default for Switch {
    fn default() -> Self {
        Switch { stacks: Stacks::K }
    }
}

struct USDT {
    binary: PathBuf,
}

struct Profile {
    stacks: Stacks,
    frequency: u64,
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

struct Rss {
    stacks: Stacks,
    throttle: u64,
}

impl<'a> TryFrom<Split<'a, char>> for Rss {
    type Error = anyhow::Error;

    fn try_from(value: Split<char>) -> Result<Self> {
        let mut rss = Rss::default();
        for item in value.take(2) {
            let maybe_stacks: Result<Stacks> = item.try_into();
            let maybe_throttle = item.parse::<u64>();
            match (maybe_stacks, maybe_throttle) {
                (Ok(stacks), Err(_)) => {
                    rss.stacks = stacks;
                }
                (Err(_), Ok(throttle)) => {
                    rss.throttle = throttle;
                }
                (Err(_), Err(_)) => anyhow::bail!("invalid configuration item for rss {}", item),
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
            throttle: 1,
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
