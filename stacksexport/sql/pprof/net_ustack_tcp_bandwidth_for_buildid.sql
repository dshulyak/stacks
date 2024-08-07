select
    ustack,
    count(*) as count,
    sum(amount) as bandwidth
from
    stacks
where
    kind in ('tcp_send', 'tcp_recv') and buildid = decode('?buildid', 'hex')
group by
    ustack