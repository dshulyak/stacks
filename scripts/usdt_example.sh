#!/bin/bpftrace

usdt:$1:past_tracing:enter
{
    printf("enter %lx %lx %lx %lx %s\n", arg0, arg1, arg2, arg3, str(arg4));
}

usdt:$1:past_tracing:exit
{   
    printf("exit %lx\n", arg0);
}

usdt:$1:past_tracing:close
{   
    printf("close %lx\n", arg0);
}