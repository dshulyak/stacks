with async_wait as (
    select
        ustack,
        kind,
        COALESCE(
            LEAD(timestamp - duration) OVER (
                PARTITION BY pid, span_id
                ORDER BY timestamp - duration
            ),
            (SELECT MAX(timestamp) FROM stacks)
        ) as next_task_started,
        timestamp as task_yielded
    from
        stacks
    where
        kind in ('trace_exit', 'trace_close')
)
select
    ustack as stack,
    count(*) as count,
    sum(next_task_started - task_yielded) as wait_ns
from
    async_wait
where kind in ('trace_exit')
group by
    stack