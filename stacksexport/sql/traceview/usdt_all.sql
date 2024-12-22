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
where kind in ('trace_exit', 'trace_close')
order by start, pid