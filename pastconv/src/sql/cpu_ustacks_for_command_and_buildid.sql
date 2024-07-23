select
    ustack,
    count(*) as count,
    sum(duration) as sampled_duration
from
    stacks
where
    kind = 'perf' and buildid = decode('?buildid', 'hex')
group by
    ustack