select
    timestamp,
    duration,
    cpu,
    tgid,
    pid,
    command,
    ustack,
    kstack
from
    stacks
where
    kind = 'switch'