#!/bin/bash

# Generate data and format it as TSV
bpftool prog show -j |
    jq --arg comm "$1" '.[] | 
    select((.pids // [])[] | 
    .comm == $comm)' |
    jq '{command_name: .name, run_cnt: (.run_cnt // 0), run_time_ns: (.run_time_ns // 0)}' |
    jq 'select(.run_cnt != 0 and .run_time_ns != 0) | . + {avg_run_time_ns: (.run_time_ns / .run_cnt)}'