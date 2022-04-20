import os
import shlex
import binascii
import capstone
import capstone.x86

import traceanalyzer.model
import traceanalyzer.debug as debug

START_TRACE = '-----BEGIN TRACE-----'
END_TRACE = '-----END TRACE-----'

class Analyzer:
    def __init__(self, trace, output, arch_mode=capstone.CS_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.output = output
        self.traces = self.read_traces()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True
        self.model = traceanalyzer.model.Model()

    def read_traces(self):
        ret = []

        content = self.read_file()

        try:
            while True:
                start = content.index(START_TRACE) + 1
                end = content.index(END_TRACE)
                ret.append(content[start:end])
                content = content[end+1:]
        except ValueError:
            pass

        ret = self.trace_to_dict(ret)

        if ret:
            debug.info(f'{self.tracefile}: {len(ret)} trace/s imported')
        else:
            debug.warning(f'{self.tracefile}: No trace found')

        return ret

    def read_file(self):
        with open(self.tracefile, 'r') as f:
            return f.read().splitlines()

    def trace_to_dict(self, traces):
        ret = []

        for trace in traces:
            list_dict = []
            for line in trace:
                try:
                    new_dict = {}
                    splitted = shlex.split(line)
                    for (key, value) in [item.split('=') for item in splitted]:
                        new_dict[key] = value
                    list_dict.append(new_dict)
                except ValueError as e:
                    debug.error(f'Parsing error: {str(e)}: {line}')
            ret.append(list_dict)

        return ret

    def analyze(self):
        try:
            for trace in self.traces:
                net_traces = self.split_network_activity(trace)
                for net_trace in net_traces:
                    self.analyze_net_trace(net_trace)
        finally:
            with open(self.output, 'w') as f:
                f.write(self.model.dump())

    def split_network_activity(self, trace):
        """
        Split traces based in recv calls

        :param trace: list of traces
        :returns: a new list of traces from a recv call until the next
        """
        ret = []
        last = 0

        for (i, line) in enumerate(trace):
            if line['action'] == 'recv':
                ret.append(trace[last:i])
                last = i

        return ret

    def analyze_net_trace(self, net_trace):
        message = None

        for trace in net_trace:
            if trace['action'] == 'recv':
                buffer_content = trace['buffer-content']
                buffer_base_address = int(trace['range-start'], 16)
                message = traceanalyzer.model.Message(buffer_content)
            elif trace['action'] == 'send':
                continue
            elif trace['level'] == 'taint':
                if trace['action'] == 'mem-read':
                    mem_read = int(trace['mem-addr'], 16)
                    ins_bytes = binascii.unhexlify(trace['ins-bytes'])
                    ins_addr = int(trace['ins-addr'], 16)
                    ins = next(self.md.disasm(ins_bytes, ins_addr))     # Just one instruction
                    message = self.analyze_ins(message, ins, mem_read, buffer_base_address)
                else:
                    debug.error(f'Not implemented: {trace}\n')

        if message: self.model.update(message)

    def analyze_ins(self, message, ins, mem_read, buffer_base_address):
        if ins.id == capstone.x86.X86_INS_CMP:
            for i in ins.operands:
                if i.type == capstone.x86.X86_OP_IMM:
                    where = mem_read - buffer_base_address
                    message.constrain(where, i.value.imm)

        return message
