SELECT
    tgid,
    pid,
    (
        LEAD(timestamp - duration) OVER (
            PARTITION BY pid
            ORDER BY
                timestamp
        )
    ) - (timestamp) AS offcpu,
    kstack
FROM
    stacks
WHERE
    tgid == ?tgid
    AND kind = 'switch'
ORDER BY
    timestamp