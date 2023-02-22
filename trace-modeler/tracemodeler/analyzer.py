import os
import shlex
import capstone
import capstone.x86

""" Set auto local for user messages """
import locale
locale.setlocale(locale.LC_ALL, '')     # '' means auto

import tracemodeler.model
import tracemodeler.debug as debug

class Analyzer:
    def __init__(self, trace, arch_mode=capstone.CS_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.traces = self.read_traces()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True
        self.fsm = tracemodeler.model.ProtocolFSM()

    def read_traces(self):
        content = self.read_file()
        debug.info(f'Parsing {len(content):n} records...')

        return self.trace_to_dict(content)

    def read_file(self):
        with open(self.tracefile, 'r') as f:
            return f.read().splitlines()

    def trace_to_dict(self, traces):
        ret = []

        for (i, trace) in enumerate(traces, start=1):
            try:
                new_dict = {}
                splitted = shlex.split(trace)
                for (key, value) in [item.split('=') for item in splitted]:
                    new_dict[key] = value
                ret.append(new_dict)
            except ValueError as e:
                debug.error(f'Parsing error: {str(e)}: line {i}: "{trace}"')

        return ret

    def analyze(self):
        """
        Traces are divided by:
            1. Session trace: each client session delimited by accepting a new connection
                                and closing its corresponding socket
            2. Network trace: each recv and send action during a session trace
        
        We restart the FSM construction for every new session
        """
        sessions = self.split_sessions()
        debug.info(f'{len(sessions)} session/s found')

        for session in sessions:
            """ Start construction of FSM by each session """
            self.fsm.initialize()

            """ Only use taint information """
            session_trace = [item for item in session if item['level'] == 'taint']

            for net_trace in self.split_network_activity(session_trace):
                self.analyze_net_trace(net_trace)

        return self.fsm

    def split_sessions(self):
        ret = []

        (index, fd) = (None, None)

        """ Asume there will be always a close call matching the file descriptor of a accept call """
        for (i, trace) in enumerate(self.traces):
            if 'action' in trace:
                if (fd is None) and (trace['action'] == 'accept'):
                    (index, fd) = (i, trace['return'])
                elif fd is not None:
                    """ Duplicate file descriptor """
                    if trace['action'] == 'dup2':
                        fd = trace['return']
                    elif (trace['action'] == 'close') and (fd == trace['file-descriptor']):
                        ret.append(self.traces[index:i])
                        (index, fd) = (None, None)

        return ret

    def split_network_activity(self, session):
        """
        Split traces based in recv/read calls

        :param session: list of traces in a client session
        :returns: a new list of traces from a recv/read call until the next
        """
        ret = []
        last = 0

        for (i, item) in enumerate(session):
            if ('action' in item) and (item['action'] in ['recv', 'read']):
                ret.append(session[last:i])
                last = i

        """ Include remaining trace """
        ret.append(session[last:])

        return ret

    def create_message(self, net_trace):
        trace = net_trace[0]    # Asumme recv trace is in first position

        if trace['level'] == 'taint':
            if trace['action'] in ['recv', 'read']:
                if int(trace['return']) >= 0:
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
