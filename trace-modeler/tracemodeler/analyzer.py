import os
import shlex
import capstone
import capstone.x86

""" Set auto local for user messages """
import locale
locale.setlocale(locale.LC_ALL, '')     # '' means auto

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
            try:
                start = content.index(START_TRACE) + 1
                end = content.index(END_TRACE)
            except ValueError as e:
                cause = str(e).split('\'')[1]
                debug.error(f'{self.tracefile}: Unable to parse file: Could not find \"{cause}\" marker')

            ret.append(content[start:end])
            content = content[end+1:]

        if ret:
            debug.info(f'{self.tracefile}: {len(ret)} execution trace/s imported')
        else:
            debug.warning(f'{self.tracefile}: No trace found')

        count = 0
        for trace in ret:
            count += len(trace)

        debug.info(f'Parsing {count:n} records...')

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
        """
        Traces are divided by:
            1. Execution trace: each time the program is executed under the server-tracer DBI module
            2. Session trace: each client session delimited by accepting a new connection
                                and closing its corresponding socket
            3. Network trace: each recv and send action during a session trace
        
        We restart the FSM construction for every new session in an execution trace
        """
        for (i, execution_trace) in enumerate(self.traces, start=1):
            sessions = self.split_sessions(execution_trace)
            debug.info(f'{len(sessions)} session/s in execution trace no. {i}')

            for session in sessions:
                """ Start construction of FSM by each session """
                self.fsm.initialize()

                """ Only use taint information """
                session_trace = [item for item in session if item['level'] == 'taint']

                for net_trace in self.split_network_activity(session_trace):
                    self.analyze_net_trace(net_trace)

        return self.fsm

    def split_sessions(self, execution_trace):
        ret = []

        """ Search for either accept new connection or close current ones """
        fd_actions = [trace for trace in execution_trace if 'action' in trace and trace['action'] in ['accept', 'close']]
        
        accept = None
        close = None

        """ Asumme there will be always a close call matching the file descriptor of a connect call """
        for fd_action in fd_actions:
            if fd_action['action'] == 'accept':
                accept = fd_action
            elif fd_action['action'] == 'close':
                close = fd_action

            if (accept is not None) and (close is not None):        
                if accept['file-descriptor'] == close['file-descriptor']:
                    ret.append(execution_trace[execution_trace.index(accept):execution_trace.index(close)])

        return ret

    def split_network_activity(self, session):
        """
        Split traces based in recv calls

        :param session: list of traces in a client session
        :returns: a new list of traces from a recv call until the next
        """
        ret = []
        last = 0

        for (i, item) in enumerate(session):
            if ('action' in item) and (item['action'] == 'recv'):
                ret.append(session[last:i])
                last = i

        """ Include remaining trace """
        ret.append(session[last:])

        return ret

    def create_message(self, net_trace):
        trace = net_trace[0]    # Asumme recv trace is in first position

        if trace['level'] == 'taint':
            if trace['action'] == 'recv':
                if int(trace['content-size']) >= 0:
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
