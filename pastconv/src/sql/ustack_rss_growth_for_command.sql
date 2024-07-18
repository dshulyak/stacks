with rss_growth as (
    select
        ustack,
        amount - (
            LAG(amount) OVER (
                PARTITION BY tgid
                ORDER BY
                    timestamp
            )
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
group by
    ustack
order by
    total_rss desc