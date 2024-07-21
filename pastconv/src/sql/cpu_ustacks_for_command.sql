select
    ustack,
    count(*),
    sum(duration),
    ustack_address,
    ustack_offset
from
    stacks
where
    kind = 'perf' and command = '?command'
group by
    ustack, ustack_address, ustack_offset
