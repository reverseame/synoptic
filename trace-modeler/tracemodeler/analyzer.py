import os
import shlex
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

        while content:
            start = content.index(START_TRACE) + 1
            end = content.index(END_TRACE)
            ret.append(content[start:end])
            content = content[end+1:]

        if ret:
            debug.info(f'{self.tracefile}: {len(ret)} trace/s imported')
        else:
            debug.warning(f'{self.tracefile}: No trace found')

        ret = self.trace_to_dict(ret)

        return ret

    def read_file(self):
        with open(self.tracefile, 'r') as f:
            return f.read().splitlines()

    def trace_to_dict(self, traces):
        ret = []

        for trace in traces:
            list_dict = []
            for (i, line) in enumerate(trace, start=1):
                try:
                    new_dict = {}
                    splitted = shlex.split(line)
                    for (key, value) in [item.split('=') for item in splitted]:
                        new_dict[key] = value
                    list_dict.append(new_dict)
                except ValueError as e:
                    debug.error(f'Parsing error: {str(e)}: line {i}: "{line}"')
            ret.append(list_dict)

        return ret

    def analyze(self):
        for trace in self.traces:
            trace = [item for item in trace if item['level'] == 'taint']    # Only use taint information

            net_traces = self.split_network_activity(trace)
            for net_trace in net_traces:
                self.analyze_net_trace(net_trace)

        return self.fsm

    def split_network_activity(self, trace):
        """
        Split traces based in recv calls

        :param trace: list of traces
        :returns: a new list of traces from a recv call until the next
        """
        ret = []
        last = 0

        for (i, item) in enumerate(trace):
            if ('action' in item) and (item['action'] == 'recv'):
                ret.append(trace[last:i])
                last = i

        # Include remaining trace
        ret.append(trace[last:i])

        return ret

    def create_message(self, net_trace):
        trace = net_trace[0]    # recv trace should be in first position

        if trace['level'] == 'taint':
            if trace['action'] == 'recv':
                buffer_content = trace['buffer-content']
                #buffer_base_address = int(trace['range-start'], 16)
                message = tracemodeler.model.Message(buffer_content)
                return message

        return None

    def analyze_net_trace(self, net_trace):
        """ Create message of recv data """
        message = self.create_message(net_trace)

        if message is not None:
            self.fsm.append(message)
