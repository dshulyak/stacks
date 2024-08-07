select
    ustack,
    count(*) as count,
    sum(amount) as bandwidth
from
    stacks
where
    kind in ('udp_recv', 'udp_send') and buildid = decode('?buildid', 'hex')
group by
    ustack