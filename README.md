# protocol-modeler

This project aims to infer the protocol message format and protocol finite state machine of an unknown protocol. This project relies on PIN Dynamic Binary Instrumentation to dynamically analize the server implementing the target protocol during its normal execution.

# Requisites

- Pin 3.22

# Structure

`server-tracer`: Pin tool that generate execution traces

`trace-analyzer`: script to analyze the execution trace and generate the protocol model

`message-replayer`: script to send messages based on the protocol model

# Compilation and Usage

1. Export the following variable in your `.bashrc` file:
    ```Bash
    export PIN_ROOT="/path/to/pin-3.22"
    ```
(Optional) Pin 3.22 in Linux gives a compilation error: you have to rename `extras/components/include/atomic/intel64/ops-impl-intel6` file to `ops-impl-intel64-asm.hpp`.

2. `make` will create the Pin's `server-tracer.so` tool under `obj-intel64` folder

3. You can now run the following command to obtain execution `trace.log`:
    ```Bash
    pin -t obj-intel64/server-tracer.so -- server-executable [args]
    ```

# TODO

1. Obtain an execution trace on how tainted buffers (from recv/send functions) are parsed
2. Analyze the execution trace to identify messages and message exchanges
3. Create the protocol model

# Ideas

- Could symbolic execution improve state discovery?
- Replay messages to analyze how new messages are parsed?
- Network trace could be good to replay function?
