select
    ustack,
    count(*),
    sum(duration)
from
    stacks
where
    kind = 'perf'
    and command = '?command'
group by
    ustack