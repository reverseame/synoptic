# Synoptic

Synoptic (**SY**mbolic **N**etw**O**rk **P**ro**T**ocol **I**nferen**C**e) is a project that aims to infer protocol message format and the protocol finite state machine (FSM) of an unknown protocol. This project mixes [Pin dynamic binary instrumentation framework](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html) and symbolic execution ([angr](https://github.com/angr/angr), [binsec](https://github.com/binsec/binsec)) to dynamically analyze the server implementing the target protocol during its normal execution.

## Project structure

Synoptic is a Python script that orchestrates two submodules:

- `servertracer`: Pintool that generates execution traces

- `tracemodeler`: Python script that analyzes the execution trace and generates the protocol FSM and message format. It also replays messages to a server based on the protocol FSM and generates new messages found by symbolic analysis

## Requisites

- `servertracer`:
  - Linux: [Pin 3.25](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.25-98650-g8f6168173-gcc-linux.tar.gz)
  - Windows: [Pin 3.25](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.25-98650-g8f6168173-gcc-linux.tar.gz), [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) (tested on version 2022) with C++ Desktop workload
- `tracemodeler`: [Python](https://www.python.org/), [pip](https://pip.pypa.io/en/stable/), [requirements.txt dependencies](trace-modeler/requirements.txt), and [radare2 5.8.4](https://github.com/radareorg/radare2/releases/tag/5.8.4). Optionally, you need to install [binsec](https://github.com/binsec/binsec) to use it as a symbolic engine

## Installation

See [INSTALL.md](INSTALL.md) to install `servertracer` and `tracemodeler` submodules.

## Usage

```console
$ python synoptic.py -h
usage: synoptic.py [-h] [-v] [--force-overwrite] [--debug]
                   [--log <file> [<file> ...]] [--dirlog <folder>] [--m32]
                   [--fsm-export <file>] [--fsm-import <file>]
                   [--fsm-pdf <file>] [--cfg-pdf <file>] [--symbolic-analysis]
                   [--binary <file>] [--symbolic-engine <angr|binsec>]
                   [--timeout <s>] [--replay] [--server-ip <ip>]
                   [--server-port <port>] [--transport-layer <tcp|udp>]
                   [--delay <ms>] [--new-messages]

   __            __   __  ___    __ 
  (__' \_/ |\ | /  \ |__)  |  | /  `
  .__)  |  | \| \__/ |     |  | \__,

This script orchestrates the generation and analysis of server execution traces to infer
the Finite-State Machine (FSM) protocol, and uses symbolic analysis to attempt to find
new messages not contained in the traces. It relies on the construction of a Dynamic
Control-Flow Graph (CFG) from traces to analyze the execution flow of a program

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         display version and exit
  --force-overwrite     force overwriting of existing files
  --debug               display debug messages
  --log <file> [<file> ...]
                        a list of .log files
  --dirlog <folder>     a folder with .log files
  --m32                 traces are in 32-bit mode (64-bit by default)
  --fsm-export <file>   export FSM to JSON file
  --fsm-import <file>   import FSM from JSON file
  --fsm-pdf <file>      create a PDF with the FSM
  --cfg-pdf <file>      create a PDF with the dynamic CFG
  --symbolic-analysis   activate symbolic analysis
  --binary <file>       binary file to add static information to the dynamic
                        CFG
  --symbolic-engine <angr|binsec>
                        symbolic engine to use for new message inference
                        (default to angr)
  --timeout <s>         symbolic exploration timeout, it is reset after each
                        result found (default to 5 s)
  --replay              send messages to a server based on the FSM
  --server-ip <ip>      server IP
  --server-port <port>  server listening port
  --transport-layer <tcp|udp>
                        transport layer (default to TCP)
  --delay <ms>          delay between messages to be sent (in ms) (default to
                        200 ms)
  --new-messages        generate and send new messages based on symbolic
                        analysis information

usage examples:
    Display a protocol FSM based on a trace:
        $ python synoptic.py --log /path/to/trace.log

    Export a protocol FSM for future use:
        $ python synoptic.py --log /path/to/trace.log --fsm-export /path/to/fsm.json

    Create dynamic CFG and FSM PDF files:
        $ python synoptic.py --log /path/to/trace.log --cfg-pdf /path/to/cfg.pdf --fsm-pdf /path/to/fsm.pdf

    Infer new keywords through symbolic analysis and export them to the FSM:
        $ python synoptic.py --log /path/to/trace.log --fsm-export /path/to/fsm.json --symbolic-analysis --binary /path/to/binary

    Replay messages to a server based on a previously exported FSM:
        $ python synoptic.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port>

    Replay FSM messages and send new messages obtained through symbolic analysis:
        $ python synoptic.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port> --new-messages
```

### server-tracer

If you only need to execute `servertracer` submodule:

```console
$ $PIN_ROOT/pin -follow_execv -t /absolute/path/to/synoptic/servertracer/obj-intel64/server_tracer.so -h -- /usr/bin/true

This tool is part of
   __            __   __  ___    __ 
  (__' \_/ |\ | /  \ |__)  |  | /  `
  .__)  |  | \| \__/ |     |  | \__,

This pintool traces all data activity sent and received over the network

Pin tools switches

-debug  [default 0]
	Enable debug messages
-dirlog  [default .]
	Absolute path of log directory (default to current directory)
```

## License

Licensed under the [GNU GPLv3](LICENSE.md) license.
