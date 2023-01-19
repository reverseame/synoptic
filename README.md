# protocol-modeler

This project aims to infer the protocol message format and protocol finite state machine of an unknown protocol. This project mixes [Pin dynamic binary instrumentation framework](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html) and symbolic execution to dynamically analyze the server implementing the target protocol during its normal execution.

## Structure

This project is divided in two modules:

- `server-tracer`: Pintool that generate execution traces.

- `trace-modeler`: Python script to analyze the execution trace and generate the protocol model (protocol FSM and message format). It also sends messages based on the protocol model.

## Requisites

- `server-tracer`:
  - Linux: [Pin 3.25](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html)
  - Windows: [Pin 3.25](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html), [Visual Studio Community](https://visualstudio.microsoft.com/es/vs/community/) (tested on version 2022) with C++ Desktop workload
- `trace-modeler`: [Python](https://www.python.org/) and [pip](https://pip.pypa.io/en/stable/)

## Installation

See [INSTALL.md](INSTALL.md) to install `server-tracer` and `trace-modeler` modules.

## Usage 

## server-tracer

```console
$ $PIN_ROOT/pin -follow_execv -t /absolute/path/to/protocol-modeler/server-tracer/obj-intel64/server_tracer.so -h -- /usr/bin/true

This Pintool traces all data activity sent and received over the network

Pin tools switches

-debug  [default 0]
	Enable debug messages
-log  [default trace.log]
	Absolute path of log filename (default to trace.log in current
	directory)
```

## trace-modeler

```console
$ python3 modeler.py -h
usage: modeler.py [-h] [-v] [--trace <log>] [--m32] [--output <file>] [--replay] [--fsm <file>] [--export <file>] [--host <ip>] [--port <port>] [--udp] [--delay DELAY]

This tool analyze a server execution trace to model a server protocol and generate new messages based in this model

optional arguments:
  -h, --help       show this help message and exit
  -v, --version    display version and exit
  --trace <log>    specify the server execution trace
  --m32            trace of a 32-bit program (64-bit by default)
  --output <file>  output protocol model file
  --replay         replay messages based in a model
  --fsm <file>     specify the protocol FSM
  --export <file>  export Graphviz file (.gv) representing the protocol FSM
  --host <ip>      server IP
  --port <port>    server listening port
  --udp            UDP transport protocol (TCP by default)
  --delay DELAY    delay between send calls (default to 0.5 s)

usage examples:
    Print generated model:
        $ python trace-modeler/modeler.py --trace /path/to/trace.log

    Export a model to an output file:
        $ python trace-modeler/modeler.py --trace /path/to/trace.log --output /path/to/model.json

    Replay messages to a host based on a model generated from a trace file:
        $ python trace-modeler/modeler.py --trace /path/to/trace.log --replay --host 127.0.0.1 --port 21

    Replay messages to a host based on an already generated model:
        $ python trace-modeler/modeler.py --model /path/to/model.json --replay --host 127.0.0.1 --port 21

    Export a model and also replay messages to a host:
        $ python trace-modeler/modeler.py --trace /path/to/trace.log --output /path/to/model.json --replay --host 127.0.0.1 --port 21

    Export graphviz .gv and .pdf files:
        $ python trace-modeler/modeler.py --trace /path/to/trace.log --export /path/to/filename
```

## Ideas
- Could symbolic execution improve state discovery?
- Replay messages to analyze how new messages are parsed?
- Network trace could be good to replay function?
