select
    ustack,
    count(*) as count,
    sum(duration) as duration
from
    stacks
where
    kind in ('blk_read', 'blk_write') and buildid = decode('?buildid', 'hex')
group by
    ustack