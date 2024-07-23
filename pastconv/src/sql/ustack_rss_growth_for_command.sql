with rss_growth as (
    select
        ustack,
        amount,
        LAG(amount) OVER (
            PARTITION BY tgid
            ORDER BY
                timestamp
        ) as prev_amount
    from
        stacks
    where
        kind = 'rss'
        and command = '?command'
        and not empty(ustack)
)
select
    ustack,
    count(*) as count,
    sum(amount - prev_amount) as total_rss
from
    rss_growth
where
    amount > prev_amount
group by
    ustack
order by
    total_rss desc