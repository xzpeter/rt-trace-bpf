# Overview

This is a repo that keeps RT related tracing tools implemented using eBPF.
Currently it only contains rt-trace-bcc.py.

# rt-trace-bcc.py

rt-trace-bcc.py is a python-bcc based tool for tracking RT related issues.
When it's executed in the background, it'll dump suspecious kernel func-calls
that may affect real-time determinism of target cores.  It can also record all
the relative information and report when it quits (by either Ctrl-C from the
command line, or a `kill $PID` with `SIGTERM`).

## Install dependencies

> sudo dnf install python3 python-bcc

We can also install it using pip3:

> pip3 install bcc

## How to use

A help message captured from v0.1.6:

> $ ./rt-trace-bcc.py -v
> Version: 0.1.6
>
> $ ./rt-trace-bcc.py -h
> usage: rt-trace-bcc.py [-h] [--cpu-list CPU_LIST] [--backtrace] [--debug] [--version] [--summary] [--quiet]
>
> Bcc-based trace tool for Real-Time workload.
>
> optional arguments:
>   -h, --help            show this help message and exit
>   --cpu-list CPU_LIST, -c CPU_LIST
>                         Cores to trace interruptions (e.g., 1,2-5,8)
>   --backtrace, -b       Whether dump backtrace when possible (default: off)
>   --debug, -d           Whether run with debug mode (default: off)
>   --version, -v         Dump version information (current: 0.1.6)
>   --summary, -s         Dump summary when stop/SIGINT (default: off)
>   --quiet, -q           Quiet mode; only dump summary (implies "-s" too)

Here `--cpu-list` parameter is required as the target cores of the tracing.
Normally it should be the isolated cores, or a subset of isolated cores on the
system.
