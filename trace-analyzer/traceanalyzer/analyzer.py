import os
import shlex
import binascii
import capstone
import capstone.x86

import traceanalyzer.debug as debug

START_TRACE = '-----BEGIN TRACE-----'
END_TRACE = '-----END TRACE-----'

class Analyzer:
    def __init__(self, trace, arch_mode=capstone.CS_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.traces = self.read_traces()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

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

        if ret:
            debug.info(f'{self.tracefile}: {len(ret)} trace/s imported')
        else:
            debug.warning(f'{self.tracefile}: Not trace found')

        return self.trace_to_dict(ret)

    def read_file(self):
        with open(self.tracefile, 'r') as f:
            return f.read().splitlines()

    def trace_to_dict(self, traces):
        ret = []

        for trace in traces:
            list_dict = []
            for line in trace:
                new_dict = {}
                splitted = shlex.split(line)
                for (key, value) in [item.split('=') for item in splitted]:
                    new_dict[key] = value
                list_dict.append(new_dict)
            ret.append(list_dict)

        return ret

    def analyze(self):
        for (i, trace) in enumerate(self.traces, start=1):
            print(f'*** Trace: {i} ***')
            net_traces = self.split_network_activity(trace)
            for (i, net_trace) in enumerate(net_traces, start=1):
                print(f'\nNetwork activity {i}')
                self.analyze_net_trace(net_trace)
            print()

    def split_network_activity(self, trace):
        ret = []
        start = 0

        for (i, line) in enumerate(trace):
            if line['action'] == 'recv':
                start = i
            elif line['action'] == 'send':
                """ Avoid if buffer is still not received """
                if start:
                    ret.append(trace[start:i])

        return ret

    def analyze_net_trace(self, net_trace):
        buffer_content = net_trace[0]['buffer-content']
        buffer_bytes = binascii.unhexlify(buffer_content)
        buffer_base_address = int(net_trace[0]['range'].split('-')[0], 16)

        print(f'\tMessage received: {buffer_content} ({buffer_bytes})')
        for trace in net_trace[1:]:
            if trace['level'] == 'taint':
                if trace['action'] == 'read':
                    try:
                        mem_read = int(trace['mem-addr'], 16)
                        ins_bytes = binascii.unhexlify(trace['ins-bytes'])
                        ins_addr = int(trace['ins-addr'], 16)
                        ins = next(self.md.disasm(ins_bytes, ins_addr))     # Just one instruction
                        self.analyze_ins(ins, mem_read, buffer_base_address, buffer_bytes)
                    except KeyError:
                        pass

    def analyze_ins(self, ins, mem_read, buffer_base_address, buffer_bytes):
        if ins.id == capstone.x86.X86_INS_CMP:
            for i in ins.operands:
                if i.type == capstone.x86.X86_OP_IMM:
                    where = mem_read - buffer_base_address
                    print(f'\t\t{ins.mnemonic} {ins.op_str}:')
                    print(f'\t\t\t{where}th byte: {hex(buffer_bytes[where])} compared to {hex(i.value.imm)}')
