#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "past.h"

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
} cfg = {
    .debug = false,
    .filter_tgid = false,
    .filter_comm = false,
    .switch_ustack = false,
    .switch_kstack = true,
    .perf_ustack = true,
    .perf_kstack = false,
};

// output is printed to /sys/kernel/debug/tracing/trace_pipe
#define bpf_printk_debug(fmt, ...)          \
    ({                                      \
        if (cfg.debug)                      \
            bpf_printk(fmt, ##__VA_ARGS__); \
    })

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

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
    // filtering based on ringbuf memory doesn't work on kernel used in ubuntu 22.04 distro.
    // bpf_map_lookup_elem restricted to fp, pkt, pkt_meta, map_key, map_value
    if (apply_filters(prev) > 0)
    {
        return 0;
    }
    struct switch_event *event = bpf_ringbuf_reserve(&events, sizeof(struct switch_event), 0);
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping switch event\n");
        return 0;
    }
    bpf_probe_read_kernel(&event->comm, sizeof(event->comm), &prev->comm);
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
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
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
    struct perf_cpu_event *event = bpf_ringbuf_reserve(&events, sizeof(struct perf_cpu_event), 0);
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping perf event\n");
        return 0;
    }
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
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
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
    struct task_struct *p = (void *)ctx[0];
    u64 tgid = p->tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    bpf_map_delete_elem(&filter_tgid, &tgid);
    struct process_exit_event *event = bpf_ringbuf_reserve(&events, sizeof(struct process_exit_event), 0);
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping process exit event\n");
        return 0;
    }
    event->type = TYPE_PROCESS_EXIT_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = tgid;
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
}

SEC("tp_btf/sched_process_exec")
int handle__sched_process_exec(u64 *ctx)
{
    struct task_struct *p = (void *)ctx[0];
    if (apply_filters(p) > 0)
    {
        return 0;
    }
    struct process_exec_event *event = bpf_ringbuf_reserve(&events, sizeof(struct process_exec_event), 0);
    if (!event)
    {
        bpf_printk_debug("ringbuf full. dropping process exec event\n");
        return 0;
    }
    event->type = TYPE_PROCESS_EXEC_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = p->tgid;
    bpf_probe_read_kernel(&event->comm, sizeof(event->comm), &p->comm);
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
}

SEC("usdt")
int BPF_USDT(past_tracing_enter, u64 span_id, u64 parent_span_id, u64 work_id, u64 amount, void *name)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_enter_event *event = bpf_ringbuf_reserve(&events, sizeof(struct tracing_enter_event), 0);
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
    event->work_id = work_id;
    event->amount = amount;
    bpf_probe_read_user_str(&event->name, sizeof(event->name), name);
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("usdt")
int BPF_USDT(past_tracing_exit, u64 span_id)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_exit_event *event = bpf_ringbuf_reserve(&events, sizeof(struct tracing_exit_event), 0);
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
    event->ustack = -1;
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("usdt")
int BPF_USDT(past_tracing_exit_stack, u64 span_id)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_exit_event *event = bpf_ringbuf_reserve(&events, sizeof(struct tracing_exit_event), 0);
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
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("usdt")
int BPF_USDT(past_tracing_close, u64 span_id)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    if (apply_tgid_filter(tgid) > 0)
    {
        return 0;
    }
    struct tracing_close_event *event = bpf_ringbuf_reserve(&events, sizeof(struct tracing_close_event), 0);
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
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// cargo libbpf doesn't generate bindings without definitions

struct switch_event _switch_event = {0};
struct perf_cpu_event _perf_cpu_event = {0};
struct tracing_enter_event _tracing_enter_event = {0};
struct tracing_exit_event _tracing_exit_event = {0};
struct tracing_close_event _tracing_close_event = {0};
struct process_exit_event _process_exit_event = {0};
struct process_exec_event _process_exec_event = {0};

char LICENSE[] SEC("license") = "Dual MIT/GPL";