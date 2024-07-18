with rss_growth as (
    select
        ustack,
        CAST(amount as BIGINT) - LAG(CAST(amount as BIGINT)) OVER (
            PARTITION BY tgid
            ORDER BY
                timestamp
        ) as rss
    from
        stacks
    where
        kind = 'rss'
        and command = '?command'
        and not empty(ustack)
)
select
    ustack,
    count(*) as cnt,
    sum(rss) as total_rss
from
    rss_growth
where
    rss > 0
group by
    ustack
order by
    total_rss desc