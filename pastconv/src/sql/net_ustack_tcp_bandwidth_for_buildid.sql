select
    ustack,
    count(*) as count,
    sum(amount) as bandwidth
from
    stacks
where
    kind in ('tcp_recv', 'tcp_send') and buildid = decode('?buildid', 'hex')
group by
    ustack