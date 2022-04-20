import os
import shlex
import binascii
import capstone
import capstone.x86

import traceanalyzer.debug as debug

START_TRACE = '-----BEGIN TRACE-----'
END_TRACE = '-----END TRACE-----'

class Analyzer:
    def __init__(self, trace, output, arch_mode=capstone.CS_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.ouput = self.create_output(output)
        self.traces = self.read_traces()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

    def create_output(self, output):
        filepath = os.path.abspath(output)
        try:
            return open(filepath, 'w')
        except OSError:
            debug.error(f'{filepath}: Unable to create output file')

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
                new_dict = {}
                splitted = shlex.split(line)
                for (key, value) in [item.split('=') for item in splitted]:
                    new_dict[key] = value
                list_dict.append(new_dict)
            ret.append(list_dict)

        return ret

    def analyze(self):
        try:
            for (i, trace) in enumerate(self.traces, start=1):
                self.ouput.write('=' * 80 + '\n')
                self.ouput.write(f'Trace: {i}\n')
                self.ouput.write('=' * 80)
                net_traces = self.split_network_activity(trace)
                for (i, net_trace) in enumerate(net_traces, start=1):
                    self.ouput.write('\n' + '-' * 20 + '\n')
                    self.ouput.write(f'Network activity {i}\n')
                    self.ouput.write('-' * 20 + '\n')
                    self.analyze_net_trace(net_trace)
                self.ouput.write('\n')
        finally:
            self.ouput.close()

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
        for trace in net_trace:
            if trace['action'] == 'recv':
                buffer_content = trace['buffer-content']
                buffer_bytes = binascii.unhexlify(buffer_content)
                buffer_base_address = int(trace['range-start'], 16)
                self.ouput.write(f'recv: {buffer_content} ({buffer_bytes})\n')
            elif trace['action'] == 'send':
                self.ouput.write(f'send: {trace["buffer-content"]} ({binascii.unhexlify(trace["buffer-content"])})\n')
            elif trace['level'] == 'taint':
                if trace['action'] == 'mem-read':
                    mem_read = int(trace['mem-addr'], 16)
                    ins_bytes = binascii.unhexlify(trace['ins-bytes'])
                    ins_addr = int(trace['ins-addr'], 16)
                    ins = next(self.md.disasm(ins_bytes, ins_addr))     # Just one instruction
                    self.analyze_ins(ins, mem_read, buffer_base_address, buffer_bytes)
                else:
                    self.ouput.write(f'NotImplementedError: {trace}\n')
                    raise NotImplementedError

    def analyze_ins(self, ins, mem_read, buffer_base_address, buffer_bytes):
        if ins.id == capstone.x86.X86_INS_CMP:
            for i in ins.operands:
                if i.type == capstone.x86.X86_OP_IMM:
                    where = mem_read - buffer_base_address
                    self.ouput.write(f'\t{ins.mnemonic} {ins.op_str}:\n')
                    self.ouput.write(f'\t\t{where}th byte: {hex(buffer_bytes[where])} compared to {hex(i.value.imm)}\n')
