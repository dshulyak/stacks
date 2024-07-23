select
    ustack,
    count(*) as count,
    sum(duration) as sampled_duration
from
    stacks
where
    kind = 'perf' and command = '?command'
group by
    ustack
