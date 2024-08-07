select 
    'counter' as event,
    kind,
    command as name,
    timestamp / 1000 as timestamp,
    tgid as pid,
    amount
from stacks
    where kind in ('rss')
    order by timestamp, pid