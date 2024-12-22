with async_wait as (
    select
        'complete' as event,
        kind,
        ustack as end_stack,
        tgid as pid,
        pid as tid,
        trace_name as name,
        cpu,
        timestamp as task_parked,
        LEAD(timestamp - duration) OVER (
            PARTITION BY span_id
            ORDER BY timestamp
        ) as task_wait_time
    from stacks
    where kind in ('trace_exit', 'trace_close')
    order by timestamp
)

select
    event,
    kind,
    (task_parked / 1000) as start,
    ((select max(timestamp) from stacks) - task_parked) / 1000 as duration,
    pid,
    pid as tid,
    name,
    cpu,
    end_stack
from async_wait
where kind in ('trace_exit') and task_wait_time is null
order by start, pid
