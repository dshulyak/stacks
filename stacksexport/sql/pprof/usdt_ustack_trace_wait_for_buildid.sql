with async_wait as (
    select
        ustack,
        kind,
        COALESCE(
            LEAD(timestamp - duration) OVER (
                PARTITION BY span_id
                ORDER BY timestamp
            ),
            (SELECT MAX(timestamp) FROM stacks)
        ) as next_task_started,
        timestamp as task_parked
    from
        stacks
    where
        kind in ('trace_exit', 'trace_close')
    order by timestamp
)
select
    ustack as stack,
    count(*) as count,
    sum(next_task_started - task_parked) as wait_ns
from
    async_wait
where kind in ('trace_exit')
group by
    stack