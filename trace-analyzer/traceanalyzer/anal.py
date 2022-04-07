from email.mime import base
import os
import binascii
import capstone
import capstone.x86

import traceanalyzer.debug as debug

START_TRACE = '-----BEGIN TRACE-----'
END_TRACE = '-----END TRACE-----'

class Anal:
    def __init__(self, trace):
        self.tracefile = os.path.abspath(trace)
        self.traces = self.read_traces()
        """HACK this shouldn't be hardcoded"""
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def read_traces(self):
        ret = []

        content = self.read_file()

        try:
            while True:
                start = content.index(START_TRACE)
                end = content.index(END_TRACE) + 1
                ret.append(content[start:end])
                content = content[end:]
        except ValueError:
            pass

        if ret:
            debug.info(f'{self.tracefile}: {len(ret)} trace/s imported')
        else:
            debug.warning(f'{self.tracefile}: Not trace found')

        return ret

    def read_file(self):
        with open(self.tracefile, 'r') as f:
            return f.read().splitlines()


    def analyze(self):
        for (i, trace) in enumerate(self.traces, start=1):
            print(f'\n*** Trace: {i} ***')
            net_traces = self.split_network_activity(trace)
            for (i, net_trace) in enumerate(net_traces, start=1):
                print(f'\nNetwork activity {i}')
                self.analyze_net_trace(net_trace)

    def split_network_activity(self, trace):
        ret = []
        start = 0

        for (i, line) in enumerate(trace):
            if 'All tainted information deleted' in line:
                if start:
                    ret.append(trace[start:i])
            if 'Function: recv' in line and 'Buffer Content' in line:
                start = i

        return ret

    def analyze_net_trace(self, net_trace):
        buffer_content = net_trace[0].split(';')[-1].split(':')[-1].strip()
        buffer_bytes = binascii.unhexlify(buffer_content)
        base_address = int(net_trace[1].split(';')[-1].split(':')[-1].split('-')[0].strip(), 16)

        print(f'\tMessage received: {buffer_content} ({buffer_bytes})')
        for line in net_trace[2:]:
            if '[Taint]' in line:
                if 'read]' in line and 'Instruction bytes:' in line:
                    mem_read = int(line.split(';')[3].split(' ')[1][1:], 16)
                    ins_bytes = binascii.unhexlify(line.split(';')[-1].split(':')[-1].strip())
                    ins_addr = int(line.split('@')[-1].split(':')[0], 16)
                    decode = self.md.disasm(ins_bytes, ins_addr)    # Just one instruction
                    for ins in decode:
                        if ins.id == capstone.x86.X86_INS_CMP:
                            for i in ins.operands:
                                if i.type == capstone.x86.X86_OP_IMM:
                                    where = mem_read - base_address
                                    print(f'\t\t{ins.mnemonic} {ins.op_str}:')
                                    print(f'\t\t\t{where}th byte: {hex(buffer_bytes[where])} compared to {hex(i.value.imm)}')
