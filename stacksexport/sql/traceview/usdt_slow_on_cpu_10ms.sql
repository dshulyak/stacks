select
    'complete' as event,
    kind,
    (timestamp - duration / 1000) as start,
    duration / 1000 as duration,
    tgid as pid,
    pid as tid,
    trace_name as name,
    cpu,
    ustack as end_stack
from stacks
where 
    kind in ('trace_exit')
    and
    duration > 10000000
order by start, pid