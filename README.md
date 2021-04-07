# Overview

This is a repo that keeps RT related tracing tools implemented using eBPF.
Currently it only contains rt-trace-bcc.py.

# rt-trace-bcc.py

rt-trace-bcc.py is a python-bcc based tool for tracking RT related issues.
When it's executed in the background, it'll dump suspecious kernel func-calls
that may affect real-time determinism of target cores.  It can also record all
the relative information and report when it quits (by either Ctrl-C from the
command line, or a `kill $PID` with `SIGTERM`).

It should be able to run this script on any modern kernel, however it's majorly
targeted at RHEL8.

## Install dependencies

```bash
sudo dnf install python3 python-bcc
```

We can also install it using pip3:

```bash
pip3 install bcc
```

## How to use

A help message captured from v0.1.7:

```bash
$ ./rt-trace-bcc.py -v
Version: 0.1.6

$ ./rt-trace-bcc.py -h
usage: rt-trace-bcc.py [-h] [--cpu-list CPU_LIST] [--backtrace] [--debug] [--version] [--summary] [--quiet]

Bcc-based trace tool for Real-Time workload.

optional arguments:
  -h, --help            show this help message and exit
  --cpu-list CPU_LIST, -c CPU_LIST
                        Cores to trace interruptions (e.g., 1,2-5,8)
  --backtrace, -b       Whether dump backtrace when possible (default: off)
  --debug, -d           Whether run with debug mode (default: off)
  --version, -v         Dump version information (current: 0.1.7)
  --summary, -s         Dump summary when stop/SIGINT (default: off)
  --quiet, -q           Quiet mode; only dump summary (implies "-s" too)
```

Here `--cpu-list` parameter is required as the target cores of the tracing.
Normally it should be the isolated cores, or a subset of isolated cores on the
system.

## Example usage

Run below command in the background to start dumping suspecious calls to
stdout happened on cores 36-39:

```bash
$ sudo ./rt-trace-bcc.py -c 36-39
[There can be some warnings dumped; we can ignore them]
Enabled hook point: process_one_work
Enabled hook point: __queue_work
Enabled hook point: __queue_delayed_work
Enabled hook point: generic_exec_single
Enabled hook point: smp_call_function_many_cond
Enabled hook point: irq_work_queue
Enabled hook point: irq_work_queue_on
TIME(s)            COMM                 CPU  PID      MSG
0.009599293        rcuc/8               8    75       irq_work_queue_on (target=36, func=nohz_full_kick_func)
0.009603039        rcuc/8               8    75       irq_work_queue_on (target=37, func=nohz_full_kick_func)
0.009604047        rcuc/8               8    75       irq_work_queue_on (target=38, func=nohz_full_kick_func)
0.009604848        rcuc/8               8    75       irq_work_queue_on (target=39, func=nohz_full_kick_func)
0.103600589        rcuc/8               8    75       irq_work_queue_on (target=36, func=nohz_full_kick_func)
0.103604182        rcuc/8               8    75       irq_work_queue_on (target=37, func=nohz_full_kick_func)
0.103605222        rcuc/8               8    75       irq_work_queue_on (target=38, func=nohz_full_kick_func)
```

Use Ctrl-C to stop tracing.

Run below command in the background to start recording suspecious calls to
stdout happened on cores 36-39, enable backtrace, with quiet mode (so no record
is dumped immediately; the result will only be dumped in JSON when the script
quits):

```bash
$ sudo ./rt-trace-bcc.py -c 36-39 -b -q
[There can be some warnings dumped; we can ignore them]
Enabled hook point: process_one_work
Enabled hook point: __queue_work
Enabled hook point: __queue_delayed_work
Enabled hook point: generic_exec_single
Enabled hook point: smp_call_function_many_cond
Enabled hook point: irq_work_queue
Enabled hook point: irq_work_queue_on
Press Ctrl-C to show results..
^CDump summary of messages:
{
    "irq_work_queue_on (target=36, func=nohz_full_kick_func)": {
        "count": 66,
        "backtrace": [
            "irq_work_queue_on+0x1",
            "tick_nohz_dep_set_all+0x55",
            "rcu_do_batch+0x435",
            "rcu_core+0x175",
            "rcu_cpu_kthread+0xa5",
            "smpboot_thread_fn+0x1d6",
            "kthread+0x15d",
            "ret_from_fork+0x35"
        ]
    },
    "irq_work_queue (cpu=36, func=nohz_full_kick_func)": {
        "count": 1,
        "backtrace": [
            "irq_work_queue+0x1"
        ]
    },
    "__queue_work (target=36, func=vmstat_update)": {
        "count": 2,
        "backtrace": [
            "__queue_work+0x1",
            "call_timer_fn+0x32",
            "run_timer_softirq+0x482",
            "__do_softirq+0xa5",
            "run_ksoftirqd+0x38",
            "smpboot_thread_fn+0x1d6",
            "kthread+0x15d",
            "ret_from_fork+0x35"
        ]
    },
    "__queue_delayed_work (target=37, func=vmstat_update, delay=9801)": {
        "count": 1,
        "backtrace": [
            "__queue_delayed_work+0x1",
            "queue_delayed_work_on+0x36",
            "process_one_work+0x18f",
            "worker_thread+0x30",
            "kthread+0x15d",
            "ret_from_fork+0x35"
        ]
    },
    ...
}
```
