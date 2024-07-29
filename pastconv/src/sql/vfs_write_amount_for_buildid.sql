select
    ustack,
    count(*) as count,
    sum(amount) as bytes
from
    stacks
where
    kind in ('vfs_write') and buildid = decode('?buildid', 'hex')
group by
    ustack