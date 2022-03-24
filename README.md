# protocol-modeler

This project aims to infer the protocol message format and protocol finite state machine of an unknown protocol. This project relies on PIN Dynamic Binary Instrumentation to dynamically analize the server implementing the target protocol during its normal execution.

# TODO

1. Obtain an execution trace on how tainted buffers (from recv/send functions) are parsed
2. Analyze the execution trace to identify messages and message exchanges
3. Create the protocol Finite State Machine

# Ideas
- Could symbolic execution improve state discovery?
