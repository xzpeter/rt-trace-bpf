#!/usr/bin/env python3
#
# SPDX-license-identifier: Apache-2.0
#
# rt-trace.py: A bcc-based tool for tracing RT tasks.
#
# Authors: Peter Xu <peterx@redhat.com>
#
# Usage:
#   $ sudo ./rt-trace.py --cpu-list <isolcpus_list>
# Example:
#   $ sudo ./rt-trace.py --cpu-list 1,3,5,15-20
#
# Normally --cpu-list should be the isolcpus or subset of it on the RT system.
# For more help, try --help.
#
# Hooks to observe on isolcpus:
# - kprobes
#   - smp_apic_timer_interrupt/__sysvec_apic_timer_interrupt
#   - process_one_work
#   - irq_work_queue
# - tracepoints
#   - sched_switch
#   - sys_enter_clock_nanosleep
#   - sys_exit_clock_nanosleep
#
# Hooks to observe when the target is within isolcpus list (kprobes):
# - __queue_work, __queue_delayed_work (covers queue_work_on,
#     queue_work_node, queue_delayed_work_on, etc.)
# - smp_call_function_any
# - smp_call_function_many_cond (covers on_each_cpu_cond_mask,
#     smp_call_function_many, smp_call_function)
# - generic_exec_single (covers smp_call_function_single,
#     smp_call_function_single_async, smp_call_function_any)
# - irq_work_queue_on
#
# TODO:
# - Support MAX_N_CPUS to 256 cores, maybe?  Currently it's 64.
# - Allow enable/disable hooks
# - Allow specify any tracepoint, remove the tracepoint list
# - Allow capture ftrace_printk() (e.g., cyclictest message dumped to
#   ftrace buffer when threshold reached)

from bcc import BPF
import argparse
import platform
import signal
import ctypes
import json
import sys
import os
import re

VERSION = "0.1.6"

# Limit this because we use one u64 as cpumask.  Problem is BPF does not allow
# loop, so any real cpumask won't work.
MAX_N_CPUS = 64

#
# Global vars
#
# To be generated, as part of BPF program
hooks = ""
defines = ""
# Keeps a list of hooks that are enabled
hook_active_list = []
# List of cpus to trace
cpu_list = []
# BPF program pointer, etc.
bpf = None
stack_traces = None
args = None
first_ts = 0
results = {}
# When in start phase, mask out all the messages coming from current process,
# since bcc will trigger quite a few hooks below
start_phase = True
cur_pid = os.getpid()

# Detect RHEL8
if re.match(".*\.el8\..*", platform.release()):
    os_version = "rhel8"
else:
    os_version = "upstream"

def err(out):
    print("ERROR: " + out)
    exit(-1)

def _d(s):
    return s.decode("utf-8")

def parse_cpu_list(cpu_list):
    out = []
    def check_index(n):
        if n >= MAX_N_CPUS:
            err("CPU index overflow (%s>=%s)" % (n, MAX_N_CPUS))
    subsets = cpu_list.split(",")
    for subset in subsets:
        if "-" in subset:
            start, end = subset.split("-")
            start = int(start)
            end = int(end)
            if start >= end:
                err("Illegal range specified: %s-%s", (start, end))
            check_index(end)
            for i in range(int(start), int(end) + 1):
                out.append(i)
            continue
        else:
            cpu = int(subset)
            check_index(cpu)
            out.append(cpu)
    return out

def parse_args():
    global cpu_list, args
    parser = argparse.ArgumentParser(
        description='Bcc-based trace tool for Real-Time workload.')
    parser.add_argument("--cpu-list", "-c",
                        help='Cores to trace interruptions (e.g., 1,2-5,8)')
    parser.add_argument("--backtrace", "-b", action='store_true',
                        help='Whether dump backtrace when possible (default: off)')
    parser.add_argument("--debug", "-d", action='store_true',
                        help='Whether run with debug mode (default: off)')
    parser.add_argument("--version", "-v", action='store_true',
                        help='Dump version information (current: %s)' % VERSION)
    parser.add_argument("--summary", "-s", action='store_true',
                        help='Dump summary when stop/SIGINT (default: off)')
    parser.add_argument("--quiet", "-q", action='store_true',
                        help='Quiet mode; only dump summary (implies "-s" too)')
    args = parser.parse_args()
    if args.quiet:
        args.summary = True
    if args.version:
        print("Version: %s" % VERSION)
        exit(0)
    if not args.cpu_list:
        print("CPU list (--cpu-list/-c) is required.  " +
              "Please use '-h' to dump the complete help message.")
        exit(0)
    cpu_list = parse_cpu_list(args.cpu_list)
    try:
        cpu_list = parse_cpu_list(args.cpu_list)
    except:
        err("Invalid cpu list: %s" % args.cpu_list)

parse_args()

#
# To enable one tracepoint/kprobe, change "enabled" to True.
#
tracepoint_list = {
    "sched_switch": {
        "enabled": False,
        "tracepoint": "sched:sched_switch",
    },
    "clock_nanosleep_enter": {
        "enabled": False,
        "tracepoint": "syscalls:sys_enter_clock_nanosleep"
    },
    "clock_nanosleep_exit": {
        "enabled": False,
        "tracepoint": "syscalls:sys_exit_clock_nanosleep",
    },
}

def handle_func(name, event):
    return "%s (func=%s)" % (name, _d(bpf.ksym(event.args[0])))

def handle_target_func(name, event):
    return "%s (target=%d, func=%s)" % \
        (name, event.args[0], _d(bpf.ksym(event.args[1])))

def handle_queue_delayed_work(name, event):
    return "%s (target=%d, func=%s, delay=%d)" % \
        (name, event.args[0], _d(bpf.ksym(event.args[1])), event.args[2])

# These kprobes have custom hooks so they can dump more things
static_kprobe_list = {
    # TBD: track smp_apic_timer_interrupt/__sysvec_apic_timer_interrupt with:
    # _d(list(BPF.get_kprobe_functions(b".*apic_timer_interrupt"))[0])
    "process_one_work": {
        "enabled": True,
        "handler": handle_func,
    },
    "__queue_work": {
        "enabled": True,
        "handler": handle_target_func,
    },
    "__queue_delayed_work": {
        "enabled": True,
        "handler": handle_queue_delayed_work,
    },
    "generic_exec_single": {
        "enabled": True,
        "handler": handle_target_func,
    },
    "smp_call_function_many_cond": {
        "enabled": True,
        "handler": handle_func,
    },
    "irq_work_queue": {
        # FIXME: Only enable this on RHEL8 for now, since for some reason
        # upstream will fail the attach.  Same to below irq_work hooks.
        "enabled": True if os_version == "rhel8" else False,
        "handler": handle_func,
    },
    "irq_work_queue_on": {
        "enabled": True if os_version == "rhel8" else False,
        "handler": handle_target_func,
    },
}

# Main body of the BPF program
body = """
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/irq_work.h>
#include <linux/llist.h>

// Global definitions generated
GENERATED_DEFINES

struct data_t {
    u32 msg_type;
    u32 pid;
    u64 ts;
    u64 args[4];
    char comm[TASK_COMM_LEN];
    u32 cpu;
#if BACKTRACE_ENABLED
    u32 stack_id;
#endif
};

// Used to communicate with the userspace program
BPF_PERF_OUTPUT(events);
// Cpumask of which trace is enabled.  Now only covers 64 cores.
BPF_ARRAY(trace_enabled, u64, 1);

#if BACKTRACE_ENABLED
// Calltrace buffers
BPF_STACK_TRACE(stack_traces, 1024);
#endif

static inline void
fill_data(struct pt_regs *regs, struct data_t *data, u32 msg_type)
{
    data->msg_type = msg_type;
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    data->cpu = bpf_get_smp_processor_id();
#if BACKTRACE_ENABLED
    // stack_id can be -EFAULT (0xfffffff2) when not applicable
    data->stack_id = stack_traces.get_stackid(regs, 0);
#endif
    bpf_get_current_comm(data->comm, sizeof(data->comm));
}

// Base function to be called by all kinds of hooks
static inline void
kprobe_common(struct pt_regs *ctx, u32 msg_type)
{
    struct data_t data = {};
    fill_data(ctx, &data, msg_type);
    events.perf_submit(ctx, &data, sizeof(data));
}

static inline u64* get_cpu_list(void)
{
    int index = 0;

    return trace_enabled.lookup(&index);
}

static inline bool cpu_in_list(int cpu)
{
    u64 *cpu_list = get_cpu_list();

    if (cpu >= MAX_N_CPUS || !cpu_list)
        return false;

    if ((1UL << cpu) & *cpu_list)
        return true;

    return false;
}

static inline bool current_cpu_in_list(void)
{
    return cpu_in_list(bpf_get_smp_processor_id());
}

// Submit message as long as the core has enabled tracing
static inline void
kprobe_trace_local(struct pt_regs *ctx, u32 msg_type)
{
    if (current_cpu_in_list())
        kprobe_common(ctx, msg_type);
}

static inline bool
cpumask_contains_target(struct cpumask *mask)
{
    u64 *cpu_list = get_cpu_list(), *ptr = (u64 *)mask;

    if (!cpu_list || !ptr)
        return false;

    if (*cpu_list & *ptr)
        return true;

    return false;
}

/*-------------------------------*
 |                               |
 | Below are static kprobe hooks |
 |                               |
 *-------------------------------*/

#if ENABLE_PROCESS_ONE_WORK
int kprobe__process_one_work(struct pt_regs *regs, void *unused,
                             struct work_struct *work)
{
    struct data_t data = {};

    if (!current_cpu_in_list())
        return 0;

    fill_data(regs, &data, MSG_TYPE_PROCESS_ONE_WORK);
    data.args[0] = (u64)work->func;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE___QUEUE_WORK
int kprobe____queue_work(struct pt_regs *regs, int cpu, void *unused,
                         struct work_struct *work)
{
    struct data_t data = {};

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, &data, MSG_TYPE___QUEUE_WORK);
    data.args[0] = (u64)cpu;
    data.args[1] = (u64)work->func;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE___QUEUE_DELAYED_WORK
int kprobe____queue_delayed_work(struct pt_regs *regs, int cpu,
                                 void *unused, struct delayed_work *work,
                                 unsigned long delay)
{
    struct data_t data = {};

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, &data, MSG_TYPE___QUEUE_DELAYED_WORK);
    data.args[0] = (u64)cpu;
    data.args[1] = (u64)work->work.func;
    data.args[2] = (u64)delay;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE_GENERIC_EXEC_SINGLE
#if OS_VERSION_RHEL8
int kprobe__generic_exec_single(struct pt_regs *regs, int cpu,
    void *unused, void *func)
#else
int kprobe__generic_exec_single(struct pt_regs *regs, int cpu,
    call_single_data_t *csd)
#endif
{
    struct data_t data = {};

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, &data, MSG_TYPE_GENERIC_EXEC_SINGLE);
    data.args[0] = (u64)cpu;
#if OS_VERSION_RHEL8
    data.args[1] = (u64)func;
#else
    data.args[1] = (u64)csd->func;
#endif
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE_SMP_CALL_FUNCTION_MANY_COND
int kprobe__smp_call_function_many_cond(struct pt_regs *regs,
    struct cpumask *mask, void *func)
{
    struct data_t data = {};

    if (!cpumask_contains_target(mask))
        return 0;

    fill_data(regs, &data, MSG_TYPE_SMP_CALL_FUNCTION_MANY_COND);
    data.args[0] = (u64)func;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE_IRQ_WORK_QUEUE
int kprobe__irq_work_queue(struct pt_regs *regs, struct irq_work *work)
{
    struct data_t data = {};

    if (!current_cpu_in_list())
        return 0;

    fill_data(regs, &data, MSG_TYPE_IRQ_WORK_QUEUE);
    data.args[0] = (u64)work->func;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

#if ENABLE_IRQ_WORK_QUEUE_ON
int kprobe__irq_work_queue_on(struct pt_regs *regs, struct irq_work *work,
                              int cpu)
{
    struct data_t data = {};

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, &data, MSG_TYPE_IRQ_WORK_QUEUE_ON);
    data.args[0] = (u64)cpu;
    data.args[1] = (u64)work->func;
    events.perf_submit(regs, &data, sizeof(data));
    return 0;
}
#endif

GENERATED_HOOKS
"""

# Allow quitting the tracing using Ctrl-C
def int_handler(signum, frame):
    global results, args
    if args.summary:
        print("Dump summary of messages:\n")
        print(json.dumps(results, indent=4))
    exit(0)
signal.signal(signal.SIGINT, int_handler)
signal.signal(signal.SIGTERM, int_handler)

def hook_name(name):
    """Return function name of a hook point to attach"""
    return "func____" + name

def tp_append(name, _type):
    """Enable a hook with type, by appending the BPF program.  When `_type'
    is 'kprobe', need to provide subtype."""
    global hooks, hook_active_list
    # Fetch the next index to use
    index = len(hook_active_list)
    # For either tracepoints or trace-local kprobes, trace all thing
    # happened on specific cores
    hooks += """
int %s(struct pt_regs *ctx)
{
    kprobe_trace_local(ctx, %d);
    return 0;
}
""" % (hook_name(name), index)
    # Create mapping in hook_active_list
    hook_active_list.append({
        "type": "tp",
        "name": name,
    })

def print_event(cpu, data, size):
    global bpf, stack_traces, args, first_ts, start_phase, cur_pid

    event = bpf["events"].event(data)
    time_s = (float(event.ts)) / 1000000000
    if not first_ts:
        first_ts = time_s
    time_s -= first_ts
    entry = hook_active_list[event.msg_type]
    name = entry["name"]
    msg = name
    comm = _d(event.comm)

    if start_phase and cur_pid == event.pid:
        # We're duing starting phase and got an event triggered from ourselves,
        # in most case we don't care about these messages. Drop them.
        return

    # Whenever we received a real event, we start recording
    start_phase = False

    if entry["type"] == "static_kprobe":
        static_entry = static_kprobe_list[name]
        handler = static_entry["handler"]
        if handler:
            # Overwrite msg with the handler output
            msg = handler(name, event)
    if not args.quiet:
        print("%-18.9f %-20s %-4d %-8d %s" %
            (time_s, comm, event.cpu, event.pid, msg))

    if msg not in results:
        results[msg] = { "count": 1 }
    else:
        results[msg]["count"] += 1

    if args.backtrace:
        stack_id = event.stack_id
        # Skip for -EFAULT
        if stack_id != 0xfffffff2:
            bt = []
            try:
                for addr in stack_traces.walk(stack_id):
                    sym = _d(bpf.ksym(addr, show_offset=True))
                    if not args.quiet:
                        print("\t%s" % sym)
                    bt.append(sym)
                if "backtrace" not in results[msg]:
                    results[msg]["backtrace"] = bt
            except(e):
                if not args.quiet:
                    print("[detected error: %s]" % e)

def apply_cpu_list(bpf, cpu_list):
    """Apply the cpu_list to BPF program"""
    cpu_array = bpf.get_table("trace_enabled")
    out = 0
    for cpu in cpu_list:
        out |= 1 << cpu
    cpu_array[0] = ctypes.c_uint64(out)

def define_add(name, var):
    global defines
    defines += "%-10s%-50s%d\n" % ("#define", name, var)

def main():
    global bpf, stack_traces, cpu_list, body

    # Enable enabled tracepoints
    for name, entry in tracepoint_list.items():
        if not entry["enabled"]:
            continue
        tp_append(name)
    for name, entry in static_kprobe_list.items():
        index = len(hook_active_list)
        enable = "ENABLE_" + name.upper()
        msg_type = "MSG_TYPE_" + name.upper()
        define_add(enable, entry["enabled"])
        if not entry["enabled"]:
            continue
        define_add(msg_type, index)
        hook_active_list.append({
            "name": name,
            "type": "static_kprobe",
        })

    define_add("OS_VERSION_RHEL8", os_version == "rhel8")
    define_add("BACKTRACE_ENABLED", args.backtrace)
    define_add("MAX_N_CPUS", MAX_N_CPUS)

    body = body.replace("GENERATED_HOOKS", hooks)
    body = body.replace("GENERATED_DEFINES", defines)
    if args.debug:
        print(body)
        exit(0)
    bpf = BPF(text=body)

    for entry in hook_active_list:
        name = entry["name"]
        t = entry["type"]
        if t == "tp":
            entry = tracepoint_list[name]
            bpf.attach_tracepoint(tp=entry["tracepoint"], fn_name=hook_name(name))
        print("Enabled hook point: %s" % name)

    if args.backtrace:
        stack_traces = bpf.get_table("stack_traces")
    apply_cpu_list(bpf, cpu_list)

    if not args.quiet:
        print("%-18s %-20s %-4s %-8s %s" % ("TIME(s)", "COMM", "CPU", "PID", "MSG"))
    else:
        print("Press Ctrl-C to show results..")
    bpf["events"].open_perf_buffer(print_event)
    while 1:
        bpf.perf_buffer_poll()

main()
