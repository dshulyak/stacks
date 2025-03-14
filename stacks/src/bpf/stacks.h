#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define REQ_OP_MASK ((1 << 8) - 1)

#define TYPE_SWITCH_EVENT 0
#define TYPE_PERF_CPU_EVENT 1
#define TYPE_TRACING_ENTER_EVENT 2
#define TYPE_TRACING_EXIT_EVENT 3
#define TYPE_TRACING_CLOSE_EVENT 4
#define TYPE_PROCESS_EXIT_EVENT 5
#define TYPE_PROCESS_EXEC_EVENT 6
#define TYPE_RSS_STAT_EVENT 7
#define TYPE_BLK_IO_EVENT 8
#define TYPE_VFS_IO_EVENT 9
#define TYPE_UDP_RECV_EVENT 10
#define TYPE_UDP_SEND_EVENT 11
#define TYPE_TCP_RECV_EVENT 12
#define TYPE_TCP_SEND_EVENT 13

enum errors
{
    DROPPED_EVENTS
};

struct switch_event
{
    __u8 type;
    __u64 start;
    __u64 end;
    __u32 tgid;
    __u32 pid;
    __u32 cpu_id;
    __s32 ustack;
    __s32 kstack;
};

struct perf_cpu_event
{
    __u8 type;
    __u64 timestamp;
    __u32 tgid;
    __u32 pid;
    __u32 cpu_id;
    __s32 ustack;
    __s32 kstack;
};

struct process_exit_event
{
    __u8 type;
    __u64 timestamp;
    __u32 tgid;
};

struct process_exec_event
{
    __u8 type;
    __u64 timestamp;
    __u32 tgid;
    __u8 comm[TASK_COMM_LEN];
};

struct tracing_enter_event
{
    __u8 type;
    __u64 ts;
    __u32 tgid;
    __u32 pid;
    __u64 span_id;
    __u64 parent_id;
    __u64 id;
    __u64 amount;
    __u8 name[TASK_COMM_LEN];
};

struct tracing_exit_event
{
    __u8 type;
    __u64 ts;
    __u32 tgid;
    __u32 pid;
    __u32 cpu_id;
    __u64 span_id;
    __s32 ustack;
    __s32 kstack;
};

struct tracing_close_event
{
    __u8 type;
    __u64 ts;
    __u32 tgid;
    __u32 pid;
    __u32 cpu_id;
    __u64 span_id;
};

struct rss_stat_event
{
    __u8 type;
    __u32 tgid;
    __u32 pid;
    __u64 ts;
    __u64 rss;
    __s32 ustack;
    __s32 kstack;
};

struct blk_io_event
{
    __u8 type;
    __u8 rw;
    __u32 tgid;
    __u32 pid;
    __u64 start;
    __u64 end;
    __u64 size;
    __s32 ustack;
    __s32 kstack;
};

struct vfs_io_event
{
    __u8 type;
    __u8 rw;
    __u32 tgid;
    __u32 pid;
    __u64 ts;
    __u64 size;
    __s32 ustack;
    __s32 kstack;
};

struct net_io_event
{
    __u8 type;
    __u32 tgid;
    __u32 pid;
    __u64 ts;
    __u64 size;
    __s32 ustack;
    __s32 kstack;
};

#endif