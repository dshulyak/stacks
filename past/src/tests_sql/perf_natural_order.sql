select
    timestamp,
    cpu,
    tgid,
    pid,
    command,
    ustack,
    kstack
from
    stacks
where
    kind == 'perf'