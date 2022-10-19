import os
import shlex
import binascii
import capstone
import capstone.x86

import tracemodeler.model
import tracemodeler.debug as debug

START_TRACE = '-----BEGIN TRACE-----'
END_TRACE = '-----END TRACE-----'

class Analyzer:
    def __init__(self, trace, arch_mode=capstone.CS_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.traces = self.read_traces()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True
        self.fsm = tracemodeler.model.ProtocolFSM()

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
                    debug.error(f'Parsing error: {str(e)}: "{line}"')
            ret.append(list_dict)

        return ret

    def analyze(self):
        try:
            for trace in self.traces:
                for item in trace:
                    if 'image-base' in item:
                        image_base = item['image-base']
                        break
                trace = [item for item in trace if item['level'] == 'taint']    # Only use taint information
                net_traces = self.split_network_activity(trace)
                for net_trace in net_traces:
                    self.analyze_net_trace(net_trace)
                self.identify_parsing_function(image_base, net_traces)
        except Exception as e:
            debug.error(str(e))
        finally:
            return self.fsm

    def split_network_activity(self, trace):
        """
        Split traces based in recv calls

        :param trace: list of traces
        :returns: a new list of traces from a recv call until the next
        """
        ret = []
        last = 0

        for (i, line) in enumerate(trace):
            if ('action' in line) and (line['action'] == 'recv'):
                ret.append(trace[last:i])
                last = i

        return ret

    def analyze_net_trace(self, net_trace):
        message = None
        start = 0

        for (i, trace) in enumerate(net_trace):
            if trace['level'] == 'taint':
                if trace['action'] == 'recv':
                    buffer_content = trace['buffer-content']
                    buffer_base_address = int(trace['range-start'], 16)
                    message = tracemodeler.model.Message(buffer_content)
                    start = i + 1
                    break

        for trace in net_trace[start:]:
            if trace['level'] == 'taint':
                if trace['action'] == 'send':
                    continue
                if trace['action'] == 'mem-read':
                    mem_read = int(trace['mem-addr'], 16)
                    ins_bytes = binascii.unhexlify(trace['ins-bytes'])
                    ins_addr = int(trace['ins-addr'], 16)
                    ins = next(self.md.disasm(ins_bytes, ins_addr))     # Just one instruction
                    message = self.analyze_ins(message, ins, mem_read, buffer_base_address)

        if message: self.fsm.append(message)

    def analyze_ins(self, message, ins, mem_read, buffer_base_address):
        if ins.id == capstone.x86.X86_INS_CMP:
            for i in ins.operands:
                if i.type == capstone.x86.X86_OP_IMM:
                    where = mem_read - buffer_base_address
                    message.constrain(where, i.value.imm)

        return message

    def identify_parsing_function(self, image_base, net_traces):
        for trace in net_traces:
            for (i, ins) in enumerate(trace[::-1]):
                if ins['action'] == 'spread':
                    ins_bytes = binascii.unhexlify(ins['ins-bytes'])
                    ins_addr = int(ins['ins-addr'], 16)
                    ins_dis = next(self.md.disasm(ins_bytes, ins_addr))     # Just one instruction
                    if ins_dis.id == capstone.x86.X86_INS_CMP:
                        index = len(trace) - i
                        import pprint
                        print('*** Parsing function ***')
                        pprint.pprint(ins)
                        break
