with offcpu_stacks as (
    select
        ustack,
        kstack,
        (
            LEAD(timestamp - duration) OVER (
                PARTITION BY pid
                ORDER BY
                    timestamp - duration
            )
        ) - (timestamp) as offcpu
    from
        stacks
    where
        kind = 'switch'
        and command = '?command'
        and (
            not empty(ustack)
            or not empty(kstack)
        )
)
select
    array_union(kstack, ustack) as stack,
    count(*),
    sum(offcpu)
from
    offcpu_stacks
where
    (
        not empty(ustack)
        or not empty(kstack)
    )
group by
    stack