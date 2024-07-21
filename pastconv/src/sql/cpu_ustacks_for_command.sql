select
    ustack,
    count(*),
    sum(duration),
    ustack_address
from
    stacks
where
    kind = 'perf' and command = '?command'
group by
    ustack, ustack_address
