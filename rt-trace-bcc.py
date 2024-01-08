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
# - Allow enable/disable hooks
# - Allow capture ftrace_printk() (e.g., cyclictest message dumped to
#   ftrace buffer when threshold reached)

from bcc import BPF
import argparse
import platform
import signal
import ctypes
import json
import time
import sys
import os
import re

VERSION = "0.2.3"

# Must change cpumask_contains_target if this value is changed
MAX_N_CPUS = 256

#
# Global vars
#
# To be generated, as part of BPF program
hooks = ""
defines = ""
# Keeps a list of hooks that are enabled.  Note that "name" in this list is the
# real name of the hooks, e.g., when some "alternatives" got chosen it'll be
# the alternative name not the key name in static_kprobe_list.
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
tracing_started = True

# Detect RHEL8
if re.match(r".*\.el8\..*", platform.release()):
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

def merge_logs(logs):

    def entry_same(entry1, entry2):
        "Return true if same calltrace, false otherwise"
        stack1 = entry1["stack"]
        stack2 = entry2["stack"]
        l = len(stack1)
        if l != len(stack2):
            return False
        for i in range(0, l):
            if stack1[i] != stack2[i]:
                return False
        return True

    def entry_exists(target_list, entry):
        "Return -1 if entry does not exist, or index of same entry (>=0)"
        for i in range(0, len(target_list)):
            if entry_same(target_list[i], entry):
                return i
        return -1

    final = {}
    for log in logs:
        f = open(log, "r")
        data = json.loads(f.read())
        for k1 in data:
            v1 = data[k1]
            if k1 not in final:
                final[k1] = {}
            for k2 in v1:
                entry_list = v1[k2]
                if k2 not in final[k1]:
                    final[k1][k2] = []
                target_list = final[k1][k2]
                for entry in entry_list:
                    i = entry_exists(target_list, entry)
                    if i < 0:
                        target_list.append(entry)
                    else:
                        target_list[i]["count"] += entry["count"]

    print(json.dumps(final, indent=4))
    exit(0)

tracepoint_list = {}

def get_tp(name):
    results = BPF.get_tracepoints(bytes(".*:%s" % name, "utf-8"))
    if not results:
        return None
    # Use the 1st one found
    return results[0]

def parse_args():
    global cpu_list, args, tracing_started, tracepoint_list

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
                        help='Dump summary when stopped (default: off)')
    parser.add_argument("--quiet", "-q", action='store_true',
                        help='Quiet mode, dump result when stopped; efficient, but less data (default: off)')
    parser.add_argument("--wait-signal", "-w", action='store_true',
                        help='Whether we hold the tracing until receive SIGHUP (default: no)')
    parser.add_argument("--merge-logs", "-m", nargs='+',
                        help='Merge multiple logs and dump the summary')
    parser.add_argument("--show-zero-ts", "-T", action='store_true',
                        help='Show timestamps from zero (default: off)')
    parser.add_argument("--enable-tps", "-e", type=str,
                        help='Enable tracepoints (comma delimited list)')
    parser.add_argument("--user-exit-tracking", "-u", action='store_true',
                        help='Enable tracking of exits from userspace')

    args = parser.parse_args()
    if args.merge_logs:
        merge_logs(args.merge_logs)
    if args.quiet and args.summary:
        err("Parameter --quiet and --summary cannot be used together")
    if args.wait_signal:
        tracing_started = False
    if args.version:
        print("Version: %s" % VERSION)
        exit(0)
    if args.enable_tps:
        tps = args.enable_tps.split(',')
        for tp in tps:
            fulltp = get_tp(tp)
            if not tp:
                err("Tracepoint %s not found" % tp)
            tracepoint_list[tp] = { "enabled": True, "tracepoint": fulltp }
        print ("List of enabled tracepoints: ", end="")
        print (tps)
    if not args.cpu_list:
        print("CPU list (--cpu-list/-c) is required.  " +
              "Please use '-h' to dump the complete help message.")
        exit(0)
    try:
        cpu_list = parse_cpu_list(args.cpu_list)
    except:
        err("Invalid cpu list: %s" % args.cpu_list)

parse_args()

def handle_func(name, event):
    return "%s (cpu=%d, func=%s)" % (name, event.cpu, _d(bpf.ksym(event.funcptr)))

def handle_target_func(name, event):
    return "%s (target=%d, func=%s)" % \
        (name, event.args[0], _d(bpf.ksym(event.funcptr)))

def handle_queue_delayed_work(name, event):
    return "%s (target=%d, func=%s, delay=%d)" % \
        (name, event.args[0], _d(bpf.ksym(event.funcptr)), event.args[1])

def handle_resched(name, event):
    return "%s (cpu=%d => cpu=%d)" % (name, event.cpu, event.args[0])

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
        # When "alternatives" is defined, we'll use the key first, if the key
        # is not in kprobe list, switch to an alternative that exist.  Bail out
        # if all alternatives fail too.
        "alternatives": [
            # Old kernels do not have smp_call_function_many_cond, then
            # fallback to smp_call_function_many, e.g., rhel8.2.
            "smp_call_function_many",
        ],
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
    "native_smp_send_reschedule": {
        "enabled": True if platform.machine() == "x86_64" else False,
        "handler": handle_resched,
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
#include <linux/bits.h>

// Global definitions generated
GENERATED_DEFINES

struct data_t {
    // this is optional per message per message type, only set when there's a
    // target func ptr bound to the event, e.g., work ptr of queue_work_on().
    u64 funcptr;
    u32 msg_type;
#if BACKTRACE_ENABLED
    int stack_id;
    int stack_id_u;
#endif

#if POLL_MODE
    // below fields are only needed for polling mode
    u32 pid;
    u32 cpu;
    char comm[TASK_COMM_LEN];
    u64 args[2];
    u64 ts;
#endif
#if USER_EXIT_TRACKING
    // delta between user_exit and user_enter tracepoints
    u64 tdelta;
#endif
};

// Cpumask of which trace is enabled.
BPF_ARRAY(trace_enabled_cpumask, u64, MAX_N_CPUS/64);

#if WAIT_SIGNAL
// Whether trace is enabled globally
BPF_ARRAY(trace_enabled, u8, 1);
#endif

#if POLL_MODE
BPF_PERF_OUTPUT(events);
#else
BPF_HASH(output, struct data_t);
#endif

BPF_PERCPU_ARRAY(percpu_data_t, struct data_t, 1);

#if BACKTRACE_ENABLED
// Calltrace buffers
BPF_STACK_TRACE(stack_traces, 1024);
#endif

#if WAIT_SIGNAL
static inline bool
global_trace_enabled(void)
{
    int index = 0;
    return trace_enabled.lookup(&index);
}
#endif

static inline void
fill_data(struct pt_regs *regs, struct data_t *data, u32 msg_type)
{
    data->msg_type = msg_type;
#if BACKTRACE_ENABLED
    // stack_id can be -EFAULT (0xfffffff2) when not applicable
    data->stack_id = stack_traces.get_stackid(regs, 0);
    data->stack_id_u = stack_traces.get_stackid(regs, BPF_F_USER_STACK);
#endif
#if POLL_MODE
    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    data->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(data->comm, sizeof(data->comm));
#endif
}

static inline void
data_submit(struct pt_regs *ctx, struct data_t *data)
{
#if WAIT_SIGNAL
    if (unlikely(!global_trace_enabled()))
        return;
#endif

#if POLL_MODE
    events.perf_submit(ctx, data, sizeof(*data));
#else
    output.increment(*data, 1);
#endif
}

// Base function to be called by all kinds of hooks
static inline void
kprobe_common(struct pt_regs *ctx, u32 msg_type)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return;
    fill_data(ctx, data, msg_type);
    data_submit(ctx, data);
}

static inline u64* get_cpu_list(int index)
{
    return trace_enabled_cpumask.lookup(&index);
}

static inline bool cpu_in_list(unsigned int cpu)
{
    u64 *cpu_list = get_cpu_list(BIT_WORD(cpu));

    if (cpu >= MAX_N_CPUS || !cpu_list)
        return false;

    if (BIT_MASK(cpu) & *cpu_list)
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
    u64 *cpu_list, *ptr = (u64 *)mask->bits;
    int i;

    for (i = 0; i < BIT_WORD(MAX_N_CPUS); i++) {
        cpu_list = get_cpu_list(i);
        if (!cpu_list || !ptr)
            return false;
        if (*cpu_list & *ptr)
            return true;
        ptr++;
    }

    return false;
}

#if USER_EXIT_TRACKING

struct trace_user_exit_data {
    u64 ts;
};
BPF_PERCPU_ARRAY(percpu_user_exit_data, struct trace_user_exit_data, 1);

int kprobe_user_exit(struct pt_regs *ctx)
{
    int zero = 0;
    struct trace_user_exit_data *udata;

    if (!current_cpu_in_list())
        return 0;

    udata = percpu_user_exit_data.lookup(&zero);
    if (!udata)
        return 0;

    udata->ts = bpf_ktime_get_ns();
    kprobe_common(ctx, MSG_TYPE_USER_EXIT);
    return 0;
}

int kprobe_user_enter(struct pt_regs *ctx)
{
    int zero = 0;
    struct trace_user_exit_data *udata;
    struct data_t* data;

    if (!current_cpu_in_list())
        return 0;

    udata = percpu_user_exit_data.lookup(&zero);
    if (!udata)
        return 0;

    zero = 0;
    data = percpu_data_t.lookup(&zero);
    if (!data)
        return 0;

    fill_data(ctx, data, MSG_TYPE_USER_ENTER);
    data->tdelta = bpf_ktime_get_ns() - udata->ts;

    data_submit(ctx, data);
    return 0;
}

#endif


/*-------------------------------*
 |                               |
 | Below are static kprobe hooks |
 |                               |
 *-------------------------------*/

#if ENABLE_PROCESS_ONE_WORK
int kprobe__process_one_work(struct pt_regs *regs, void *unused,
                             struct work_struct *work)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!current_cpu_in_list())
        return 0;

    fill_data(regs, data, MSG_TYPE_PROCESS_ONE_WORK);
    data->funcptr = (u64)work->func;
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE___QUEUE_WORK
int kprobe____queue_work(struct pt_regs *regs, int cpu, void *unused,
                         struct work_struct *work)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, data, MSG_TYPE___QUEUE_WORK);
#if POLL_MODE
    data->args[0] = (u64)cpu;
#endif
    data->funcptr = (u64)work->func;
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE___QUEUE_DELAYED_WORK
int kprobe____queue_delayed_work(struct pt_regs *regs, int cpu,
                                 void *unused, struct delayed_work *work,
                                 unsigned long delay)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, data, MSG_TYPE___QUEUE_DELAYED_WORK);
#if POLL_MODE
    data->args[0] = (u64)cpu;
    data->args[1] = (u64)delay;
#endif
    data->funcptr = (u64)work->work.func;
    data_submit(regs, data);
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
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, data, MSG_TYPE_GENERIC_EXEC_SINGLE);
#if POLL_MODE
    data->args[0] = (u64)cpu;
#endif
#if OS_VERSION_RHEL8
    data->funcptr = (u64)func;
#else
    data->funcptr = (u64)csd->func;
#endif
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE_SMP_CALL_FUNCTION_MANY_COND
int kprobe__smp_call_function_many_cond(struct pt_regs *regs,
    struct cpumask *mask, void *func)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpumask_contains_target(mask))
        return 0;

    fill_data(regs, data, MSG_TYPE_SMP_CALL_FUNCTION_MANY_COND);
    data->funcptr = (u64)func;
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE_IRQ_WORK_QUEUE
int kprobe__irq_work_queue(struct pt_regs *regs, struct irq_work *work)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!current_cpu_in_list())
        return 0;

    fill_data(regs, data, MSG_TYPE_IRQ_WORK_QUEUE);
    data->funcptr = (u64)work->func;
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE_IRQ_WORK_QUEUE_ON
int kprobe__irq_work_queue_on(struct pt_regs *regs, struct irq_work *work,
                              int cpu)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, data, MSG_TYPE_IRQ_WORK_QUEUE_ON);
#if POLL_MODE
    data->args[0] = (u64)cpu;
#endif
    data->funcptr = (u64)work->func;
    data_submit(regs, data);
    return 0;
}
#endif

#if ENABLE_NATIVE_SMP_SEND_RESCHEDULE
int kprobe__native_smp_send_reschedule(struct pt_regs *regs, int cpu)
{
    int zero = 0;
    struct data_t* data = percpu_data_t.lookup(&zero);

    if (!data)
        return 0;

    if (!cpu_in_list(cpu))
        return 0;

    fill_data(regs, data, MSG_TYPE_NATIVE_SMP_SEND_RESCHEDULE);
#if POLL_MODE
    data->args[0] = (u64)cpu;
#endif
    data_submit(regs, data);
    return 0;
}
#endif

GENERATED_HOOKS
"""

def get_stack(stack_id, pid):
    global bpf, stack_traces
    bt = []
    if stack_id == -14:
        # -EFAULT
        return []
    if stack_id < 0:
        # Unknown error
        print("[error: stack_id=%d]" % stack_id)
        return []
    for addr in stack_traces.walk(stack_id):
        if pid == 0:
            sym = _d(bpf.ksym(addr, show_offset=True))
        else:
            sym = _d(bpf.sym(addr, pid, show_module=False, show_offset=True))
            sym = sym + "/" + hex(addr)

        bt.append(sym)
    return bt

def collect_hash_data():
    global hook_active_list, args, bpf

    results = {}
    data = list(bpf.get_table("output").items())
    data.sort(key=lambda x: x[1].value)
    for event, count in data:
        count = count.value
        hook = hook_active_list[event.msg_type]
        if event.funcptr:
            funcptr = "funcptr=%s" % _d(bpf.ksym(event.funcptr))
        else:
            funcptr = "funcptr=NULL"
        if funcptr not in results:
            results[funcptr] = {}
        name = "hook=%s" % hook["name"]
        if name not in results[funcptr]:
            results[funcptr][name] = []
        entry = { "count": count }
        if args.backtrace:
            entry["stack"] = get_stack(event.stack_id, 0)
            entry["ustack"] = get_stack(event.stack_id_u, event.pid)
        results[funcptr][name].append(entry)

    return results

# Allow quitting the tracing using Ctrl-C
def int_handler(signum, frame):
    global results

    # For poll mode, summary already in "results"
    if args.quiet:
        results = collect_hash_data()

    if args.summary or args.quiet:
        print("Dump summary of messages:\n")
        print(json.dumps(results, indent=4))

    exit(0)

signal.signal(signal.SIGINT, int_handler)
signal.signal(signal.SIGTERM, int_handler)

def hup_handler(signum, frame):
    global bpf, tracing_started

    # Enable BPF program
    enabled = bpf.get_table("trace_enabled")
    enabled[0] = ctypes.c_uint8(1)
    # Enable ourselves
    tracing_started = True

    print("Received SIGHUP, tracing started.\n")

signal.signal(signal.SIGHUP, hup_handler)

def hook_name(name):
    """Return function name of a hook point to attach"""
    return "func____" + name

def tp_append(name):
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

def static_kprobe_list_find_entry(name):
    global static_kprobe_list
    if name in static_kprobe_list:
        return static_kprobe_list[name]
    for key, entry in static_kprobe_list.items():
        if "alternatives" not in entry:
            continue
        if name in entry["alternatives"]:
            return entry
    raise Exception("Hook name '%s' not found in static_kprobe_list" % name)

def print_event(cpu, data, size):
    global bpf, stack_traces, args, first_ts, start_phase, cur_pid

    event = bpf["events"].event(data)
    time_s = (float(event.ts)) / 1000000000
    if args.show_zero_ts:
        if not first_ts:
            first_ts = time_s
        time_s -= first_ts
    entry = hook_active_list[event.msg_type]
    name = entry["name"]
    msg = "%s (cpu=%d)" % (name, event.cpu)
    comm = _d(event.comm)

    if start_phase and cur_pid == event.pid:
        # We're duing starting phase and got an event triggered from ourselves,
        # in most case we don't care about these messages. Drop them.
        return

    # Whenever we received a real event, we start recording
    start_phase = False

    if entry["type"] == "static_kprobe":
        static_entry = static_kprobe_list_find_entry(name)
        handler = static_entry["handler"]
        if handler:
            # Overwrite msg with the handler output
            msg = handler(name, event)
    if entry["type"] == "usertrack":
        if name == "user_enter":
            msg = "%s (cpu=%d) %7d ns" % (name, event.cpu, event.tdelta)

    print("%-18.9f %-20s %-4d %-8d %s" %
        (time_s, comm, event.cpu, event.pid, msg))

    if msg not in results:
        results[msg] = { "count": 1 }
    else:
        results[msg]["count"] += 1

    if args.backtrace:
        bt = get_stack(event.stack_id, 0)
        for call in bt:
            print("\t%s" % call)
        ubt = get_stack(event.stack_id_u, event.pid)
        if len(ubt) > 0:
            print("user stack:")
            for ucall in ubt:
                print("\t%s" % ucall)
        if "backtrace" not in results[msg]:
            results[msg]["backtrace"] = bt

def apply_cpu_list(bpf, cpu_list):
    """Apply the cpu_list to BPF program"""
    cpu_array = bpf.get_table("trace_enabled_cpumask")

    for cblock in range(0, int(MAX_N_CPUS/64)):
        out = 0

        for cpu in cpu_list:
            if cpu >= cblock*64 and cpu < cblock*64 + 64:
                out |= 1 << (cpu % 64)

        cpu_array[cblock] = ctypes.c_uint64(out)

def define_add(name, var):
    global defines
    defines += "%-10s%-50s%d\n" % ("#define", name, var)

def has_kprobe(name):
    "Whether kprobe existed?  Try avoid calling this since it's a bit slow"
    return bool(BPF.get_kprobe_functions(bytes("^%s$" % name, "utf-8")))

def bpf_find_kprobe(name, entry):
    if "alternatives" not in entry:
        # If not specified, just use it! (as has_kprobe is slow)
        return name
    if has_kprobe(name):
        return name
    alternatives = entry["alternatives"]
    for alt in alternatives:
        if has_kprobe(alt):
            print("Using alternative '%s' for original hook '%s'" % \
                  (alt, name))
            return alt
    raise Exception("Cannot find kprobe for entry '%s'" % name)

def get_hook_func_name(name):
    return "kprobe__%s" % name

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
        real_name = bpf_find_kprobe(name, entry)
        if name is not real_name:
            # Used one alternative hook, so need to change the hook name.  This
            # is a bit ugly, but probably simplest so far..
            old_hook = get_hook_func_name(name)
            new_hook = get_hook_func_name(real_name)
            body = body.replace(old_hook, new_hook)
        hook_active_list.append({
            "name": real_name,
            "type": "static_kprobe",
        })

    if args.user_exit_tracking:
        for name in ["user_exit", "user_enter"]:
            index = len(hook_active_list)
            msg_type = "MSG_TYPE_" + name.upper()
            define_add(msg_type, index)
            # Create mapping in hook_active_list
            hook_active_list.append({
                "type": "usertrack",
                "name": name,
            })

    define_add("OS_VERSION_RHEL8", os_version == "rhel8")
    define_add("BACKTRACE_ENABLED", args.backtrace)
    define_add("MAX_N_CPUS", MAX_N_CPUS)
    # When --quiet, we use map mode so we only collect data at the end;
    # otherwise use poll mode to fetch message one by one
    define_add("POLL_MODE", not args.quiet)
    define_add("WAIT_SIGNAL", args.wait_signal)
    define_add("USER_EXIT_TRACKING", args.user_exit_tracking)

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

    if args.user_exit_tracking:
        bpf.attach_tracepoint(tp="context_tracking:user_exit",  fn_name="kprobe_user_exit");
        bpf.attach_tracepoint(tp="context_tracking:user_enter",  fn_name="kprobe_user_enter");

    if args.backtrace:
        stack_traces = bpf.get_table("stack_traces")
    apply_cpu_list(bpf, cpu_list)

    if args.wait_signal:
        print("Please send SIGHUP to this process to start tracing..")
        while not tracing_started:
            time.sleep(0.1)

    if not args.quiet:
        print("%-18s %-20s %-4s %-8s %s" % ("TIME(s)", "COMM", "CPU", "PID", "MSG"))
        bpf["events"].open_perf_buffer(print_event)
        while 1:
            bpf.perf_buffer_poll()
    else:
        print("Press Ctrl-C to show results..")
        time.sleep(99999999)

main()
