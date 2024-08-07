#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "stacks.h"

// drop non informative kernel frames in sched_switch tracepoint
// [bpf_prog_bc47227d8acb679b_handle__sched_switch,
//  bpf_prog_bc47227d8acb679b_handle__sched_switch,
//  bpf_trace_run4,
// __bpf_trace_sched_switch,
// __traceiter_sched_switch
#define DROP_KERNEL_SCHED_SWITCH_FRAMES (5 & BPF_F_SKIP_FIELD_MASK)

#define TASK_RUNNING 0

const volatile struct
{
    bool debug;
    bool filter_tgid;
    bool filter_comm;
    bool switch_ustack;
    bool switch_kstack;
    bool perf_ustack;
    bool perf_kstack;
    bool rss_ustack;
    bool rss_kstack;
    bool blk_ustack;
    bool blk_kstack;
    bool vfs_ustack;
    bool vfs_kstack;
    bool net_ustack;
    bool net_kstack;
    __u64 wakeup_bytes;
    __u16 rss_stat_throttle;
    __u64 minimal_switch_duration;
} cfg = {
    .debug = false,
    .filter_tgid = false,
    .filter_comm = false,
    .switch_ustack = false,
    .switch_kstack = true,
    .perf_ustack = true,
    .perf_kstack = false,
    .rss_ustack = true,
    .rss_kstack = false,
    .blk_ustack = false,
    .blk_kstack = false,
    .vfs_ustack = false,
    .vfs_kstack = false,
    .net_ustack = false,
    .net_kstack = false,
    .wakeup_bytes = 10 << 10,
    .rss_stat_throttle = 0,
    .minimal_switch_duration = 0,
};

// output is printed to /sys/kernel/debug/tracing/trace_pipe
#define bpf_printk_debug(fmt, ...)          \
    ({                                      \
        if (cfg.debug)                      \
            bpf_printk(fmt, ##__VA_ARGS__); \
    })

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, DROPPED_EVENTS + 1);
} errors_counter SEC(".maps");

__always_inline void inc_dropped()
{
    u32 key = DROPPED_EVENTS;
    u64 *val = bpf_map_lookup_elem(&errors_counter, &key);
    if (val)
    {
        *val += 1;
    }
    else
    {
        u64 one = 1;
        bpf_map_update_elem(&errors_counter, &key, &one, BPF_ANY);
    }
}

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

static __always_inline void *reserve_event(__u64 size)
{
    void *event = bpf_ringbuf_reserve(&events, size, 0);
    if (!event)
    {
        inc_dropped();
    }
    return event;
}

static __always_inline void submit_event(void *event)
{
    __u64 available = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    if (available > cfg.wakeup_bytes)
    {
        return bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
    return bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
}

static __always_inline void submit_immediate(void *event)
{
    return bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
}

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u16);
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} throttle_rss_stat SEC(".maps");

static __always_inline int throttle_rss_stat_event(u32 tgid)
{
    if (cfg.rss_stat_throttle == 0)
    {
        return 0;
    }
    u16 *val = bpf_map_lookup_elem(&throttle_rss_stat, &tgid);
    if (!val)
    {
        u16 zero = 0;
        bpf_map_update_elem(&throttle_rss_stat, &tgid, &zero, BPF_ANY);
        return 0;
    }
    *val += 1;
    if (*val % cfg.rss_stat_throttle == 0)
    {
        return 0;
    }
    return 1;
}

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 8 * 1024);
} stackmap SEC(".maps");

const u32 switch_span = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} percpu_spans SEC(".maps");

__always_inline u64 record_span(u32 tag, u64 now)
{
    u64 start;
    u64 *val = bpf_map_lookup_elem(&percpu_spans, &tag);
    if (val)
    {
        start = *val;
    }
    else
    {
        start = 0;
    }
    long rst = bpf_map_update_elem(&percpu_spans, &tag, &now, BPF_ANY);
    if (rst < 0)
    {
        bpf_printk_debug("failed to update span %d\n", rst);
        return 0;
    }
    return start;
}

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} filter_tgid SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[TASK_COMM_LEN]);
    __type(value, __u8);
    __uint(max_entries, 1024);
} filter_comm SEC(".maps");

__always_inline int filters_enabled()
{
    return cfg.filter_tgid || cfg.filter_comm;
}

__always_inline int apply_tgid_filter(u32 tgid)
{
    if (!cfg.filter_tgid)
    {
        return 0;
    }
    u8 *val = bpf_map_lookup_elem(&filter_tgid, &tgid);
    if (val)
    {
        return 0;
    }
    return 1;
}

__always_inline int apply_filters(struct task_struct *task)
{
    if (!filters_enabled())
    {
        return 0;
    }

    __u32 tgid = task->tgid;
    __u8 comm[TASK_COMM_LEN];

    if (cfg.filter_tgid)
    {
        if (bpf_map_lookup_elem(&filter_tgid, &tgid))
        {
            return 0;
        }
    }
    if (cfg.filter_comm)
    {
        bpf_probe_read_kernel(&comm, sizeof(comm), &task->comm);
        const u8 *val = bpf_map_lookup_elem(&filter_comm, &comm);
        if (val)
        {
            u32 zero = 0;
            bpf_map_update_elem(&filter_tgid, &tgid, &zero, BPF_ANY);
            return 0;
        }
    }
    return 1;
}

struct recorded_blk_io_start
{
    __u64 ts;
    __u32 tgid;
    __u64 size;
    __s32 kstack;
    __s32 ustack;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct request *);
    __type(value, struct recorded_blk_io_start);
} blk_io_starts SEC(".maps");

// HANDLERS

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx[1];
    u64 end = bpf_ktime_get_ns();
    u64 start = record_span(switch_span, end);
    if (start == 0)
    {
        return 0;
    }
    if (start > end)
    {
        bpf_printk_debug("start (%d) > end %(d)\n", start, end);
        return 0;
    }
    if (prev->pid == 0)
    {
        return 0;
    }
    u32 tgid = prev->tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    u64 delta = end - start;
    if (delta < cfg.minimal_switch_duration)
    {
        bpf_printk_debug("duration (%d) is less than minimal (%d)\n", delta, cfg.minimal_switch_duration);
        return 0;
    }
    struct switch_event *event = reserve_event(sizeof(struct switch_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping switch event\n");
        return 0;
    }
    event->type = TYPE_SWITCH_EVENT;
    event->start = start;
    event->end = end;
    event->pid = prev->pid;
    event->tgid = prev->tgid;
    event->cpu_id = bpf_get_smp_processor_id();
    if (cfg.switch_ustack)
    {
        event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->ustack = -1;
    }
    if (cfg.switch_kstack)
    {
        event->kstack = bpf_get_stackid(ctx, &stackmap,
                                        BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID | DROP_KERNEL_SCHED_SWITCH_FRAMES);
    }
    else
    {
        event->kstack = -1;
    }
    submit_event(event);
    return 0;
}

SEC("perf_event")
int handle__perf_event(void *ctx)
{
    __u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (pid == 0)
    {
        return 0;
    }
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct perf_cpu_event *event = reserve_event(sizeof(struct perf_cpu_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping perf event\n");
        return 0;
    }
    event->type = TYPE_PERF_CPU_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->pid = pid;
    event->cpu_id = bpf_get_smp_processor_id();
    if (cfg.perf_ustack)
    {
        event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->ustack = -1;
    }
    if (cfg.perf_kstack)
    {
        event->kstack = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->kstack = -1;
    }
    submit_event(event);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
    struct task_struct *p = (void *)ctx[0];
    if (p->tgid != p->pid)
    {
        return 0;
    }
    u64 tgid = p->tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    bpf_map_delete_elem(&filter_tgid, &tgid);
    struct process_exit_event *event = reserve_event(sizeof(struct process_exit_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping process exit event\n");
        return 0;
    }
    event->type = TYPE_PROCESS_EXIT_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = tgid;
    submit_event(event);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int handle__sched_process_exec(u64 *ctx)
{
    struct task_struct *p = (void *)ctx[0];
    if (p->tgid != p->pid)
    {
        return 0;
    }
    if (apply_filters(p) > 0)
    {
        return 0;
    }
    struct process_exec_event *event = reserve_event(sizeof(struct process_exec_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping process exec event\n");
        return 0;
    }
    event->type = TYPE_PROCESS_EXEC_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = p->tgid;
    bpf_probe_read_kernel(&event->comm, sizeof(event->comm), &p->comm);
    submit_immediate(event);
    return 0;
}

SEC("usdt")
int BPF_USDT(stacks_tracing_enter, u64 span_id, u64 parent_span_id, u64 id, u64 amount, void *name)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_enter_event *event = reserve_event(sizeof(struct tracing_enter_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping tracing enter event\n");
        return 0;
    }
    event->type = TYPE_TRACING_ENTER_EVENT;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->pid = pid;
    event->span_id = span_id;
    event->parent_id = parent_span_id;
    event->id = id;
    event->amount = amount;
    bpf_probe_read_user_str(&event->name, sizeof(event->name), name);
    submit_event(event);
    return 0;
}

SEC("usdt")
int BPF_USDT(stacks_tracing_exit, u64 span_id)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_exit_event *event = reserve_event(sizeof(struct tracing_exit_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping tracing exit event\n");
        return 0;
    }
    event->type = TYPE_TRACING_EXIT_EVENT;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->pid = pid;
    event->cpu_id = bpf_get_smp_processor_id();
    event->span_id = span_id;
    event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    submit_event(event);
    return 0;
}

SEC("usdt")
int BPF_USDT(stacks_tracing_close, u64 span_id)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_close_event *event = reserve_event(sizeof(struct tracing_close_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping tracing close event\n");
        return 0;
    }
    event->type = TYPE_TRACING_CLOSE_EVENT;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->pid = pid;
    event->cpu_id = bpf_get_smp_processor_id();
    event->span_id = span_id;
    submit_event(event);
    return 0;
}

s64 percpu_counter_read_positive(struct percpu_counter *fbc)
{
    s64 ret;
    ret = fbc->count;
    if (ret >= 0)
        return ret;
    return 0;
}

struct mm_rss_stat___pre62
{
    atomic_long_t count[4];
} __attribute__((preserve_access_index));

struct mm_struct___pre62
{
    struct mm_rss_stat___pre62 rss_stat;
} __attribute__((preserve_access_index));

struct mm_struct___post62
{
    struct percpu_counter rss_stat[NR_MM_COUNTERS];
} __attribute__((preserve_access_index));

SEC("tp_btf/rss_stat")
int handle__mm_trace_rss_stat(u64 *ctx)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    if (throttle_rss_stat_event(tgid) > 0)
    {
        bpf_printk_debug("throttling rss stat event for tgid %d\n", tgid);
        return 0;
    }

    const struct mm_struct *mm = (void *)ctx[0];
    u64 file_pages = 0;
    u64 anon_pages = 0;
    u64 shmem_pages = 0;
    // i haven't looked why bpf_core_type_matches(struct mm_struct___pre62) doesn't match on 5.15.
    // neither bpf_core_type_matches(struct mm_struct___post62) on 6.5
    if (bpf_core_field_exists(mm->rss_stat.count))
    {
        const struct mm_struct___pre62 *mms = mm;
        file_pages = BPF_CORE_READ(mms, rss_stat.count[MM_FILEPAGES].counter);
        anon_pages = BPF_CORE_READ(mms, rss_stat.count[MM_ANONPAGES].counter);
        shmem_pages = BPF_CORE_READ(mms, rss_stat.count[MM_SHMEMPAGES].counter);
    }
    else
    {
        const struct mm_struct___post62 *mms = mm;
        struct percpu_counter file_fbc = BPF_CORE_READ(mms, rss_stat[MM_FILEPAGES]);
        struct percpu_counter anon_fbc = BPF_CORE_READ(mms, rss_stat[MM_ANONPAGES]);
        struct percpu_counter shmem_fbc = BPF_CORE_READ(mms, rss_stat[MM_SHMEMPAGES]);
        file_pages = percpu_counter_read_positive(&file_fbc);
        anon_pages = percpu_counter_read_positive(&anon_fbc);
        shmem_pages = percpu_counter_read_positive(&shmem_fbc);
    }
    u64 rss = file_pages + anon_pages + shmem_pages;

    struct rss_stat_event *event = reserve_event(sizeof(struct rss_stat_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping rss stat event\n");
        return 0;
    }
    event->type = TYPE_RSS_STAT_EVENT;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->rss = rss;
    if (cfg.rss_ustack)
    {
        event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->ustack = -1;
    }
    if (cfg.rss_kstack)
    {
        event->kstack = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->kstack = -1;
    }
    submit_event(event);
    return 0;
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *rq)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct recorded_blk_io_start recorded = {
        .ts = bpf_ktime_get_ns(),
        .tgid = tgid,
        .size = BPF_CORE_READ(rq, __data_len),
    };
    if (cfg.blk_ustack)
    {
        recorded.ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        recorded.ustack = -1;
    }
    if (cfg.blk_kstack)
    {
        recorded.kstack = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        recorded.kstack = -1;
    }
    bpf_map_update_elem(&blk_io_starts, &rq, &recorded, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_io_done")
int BPF_PROG(block_io_done, struct request *rq)
{
    struct recorded_blk_io_start *recorded = bpf_map_lookup_elem(&blk_io_starts, &rq);
    if (!recorded)
    {
        return 0;
    }
    bpf_map_delete_elem(&blk_io_starts, &rq);

    struct blk_io_event *event = reserve_event(sizeof(struct blk_io_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping block io event\n");
        return 0;
    }
    event->type = TYPE_BLK_IO_EVENT;
    event->rw = (BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK) == REQ_OP_WRITE;
    event->tgid = recorded->tgid;
    event->start = recorded->ts;
    event->end = bpf_ktime_get_ns();
    event->size = recorded->size;
    event->ustack = recorded->ustack;
    event->kstack = recorded->kstack;
    submit_event(event);
    return 0;
}

__always_inline int on_vfs_event(u64 *ctx, __u8 rw) {
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct vfs_io_event *event = reserve_event(sizeof(struct vfs_io_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping vfs read event\n");
        return 0;
    }
    event->type = TYPE_VFS_IO_EVENT;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->size = (__u64)ctx[2];
    event->rw = rw;
    if (cfg.vfs_ustack)
    {
        event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->ustack = -1;
    }
    if (cfg.vfs_kstack)
    {
        event->kstack = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->kstack = -1;
    }
    submit_event(event);
	return 0;
}

SEC("fentry/vfs_read")
int vfs_read(u64 *ctx)
{
	return on_vfs_event(ctx, 0);
}

SEC("fentry/vfs_readv")
int vfs_readv(u64 *ctx)
{
	return on_vfs_event(ctx, 0);
}

SEC("fentry/vfs_write")
int vfs_write(u64 *ctx)
{
	return on_vfs_event(ctx, 1);
}

SEC("fentry/vfs_writev")
int vfs_writev(u64 *ctx)
{
	return on_vfs_event(ctx, 1);
}

__always_inline int on_net_event(u64 *ctx, __u8 type) 
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct net_io_event *event = reserve_event(sizeof(struct net_io_event));
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping net io event\n");
        return 0;
    }
    event->type = type;
    event->ts = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->size = (__u64)ctx[2];
    if (cfg.net_ustack)
    {
        event->ustack = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->ustack = -1;
    }
    if (cfg.net_kstack)
    {
        event->kstack = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    else
    {
        event->kstack = -1;
    }
    submit_event(event);
    return 0;
}

SEC("fentry/udp_recvmsg")
int udp_recvmsg(u64 *ctx)
{
    return on_net_event(ctx, TYPE_UDP_RECV_EVENT);
}   

SEC("fentry/udp_sendmsg")
int udp_sendmsg(u64 *ctx)
{
    return on_net_event(ctx, TYPE_UDP_SEND_EVENT);
}

SEC("fentry/tcp_recvmsg")
int tcp_recvmsg(u64 *ctx)
{
    return on_net_event(ctx, TYPE_TCP_RECV_EVENT);
}

SEC("fentry/tcp_sendmsg")
int tcp_sendmsg(u64 *ctx)
{
    return on_net_event(ctx, TYPE_TCP_SEND_EVENT);
}

// cargo libbpf doesn't generate bindings without definitions

struct switch_event _switch_event = {0};
struct perf_cpu_event _perf_cpu_event = {0};
struct tracing_enter_event _tracing_enter_event = {0};
struct tracing_exit_event _tracing_exit_event = {0};
struct tracing_close_event _tracing_close_event = {0};
struct process_exit_event _process_exit_event = {0};
struct process_exec_event _process_exec_event = {0};
struct rss_stat_event _rss_stat_event = {0};
struct blk_io_event _blk_io_event = {0};
struct vfs_io_event _vfs_io_event = {0};
struct net_io_event _net_io_event = {0};

char LICENSE[] SEC("license") = "Dual MIT/GPL";