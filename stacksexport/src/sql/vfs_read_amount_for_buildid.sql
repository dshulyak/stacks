select
    ustack,
    count(*) as count,
    sum(amount) as bytes
from
    stacks
where
    kind in ('vfs_read') and buildid = decode('?buildid', 'hex')
group by
    ustack