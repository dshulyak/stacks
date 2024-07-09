select
    min(timestamp - duration) as timestamp
from
    stacks
where
    kind = 'perf';