select 
    'complete' as event,
    (timestamp - duration) / 1000 as start,
    duration / 1000 as duration,
    tgid as pid,
    pid as tid,
    command as name,
    array_union(kstack, ustack) as end_stack,
    cpu
from stacks
    where kind in ('switch')
    order by start, pid