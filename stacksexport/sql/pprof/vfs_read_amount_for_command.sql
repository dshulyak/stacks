select
    ustack,
    count(*) as count,
    sum(amount) as bytes
from
    stacks
where
    kind in ('vfs_read') and command = '?command'
group by
    ustack