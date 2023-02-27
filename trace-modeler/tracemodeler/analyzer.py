import os
import shlex
import unicorn
import unicorn.x86_const
import binascii

""" Set auto local for user messages """
import locale
locale.setlocale(locale.LC_ALL, '')     # '' means auto

import tracemodeler.model
import tracemodeler.debug as debug

class Analyzer:
    def __init__(self, trace, arch_mode=unicorn.UC_MODE_64):
        self.tracefile = os.path.abspath(trace)
        self.traces = self.read_traces()
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, arch_mode)
        self.mu_addr = self._set_up_unicorn_engine()
        self.fsm = tracemodeler.model.ProtocolFSM()

    def _set_up_unicorn_engine(self):
        """
        Set up executable memory range
        """
        trace = self.traces[1]
        assert trace['action'] == 'relocate'

        image_low = int(trace['image-low'], 16)

        self.mu.mem_map(image_low, 4 * 1024, perms=unicorn.UC_PROT_EXEC)      # One executable page of 4 KiB

        return image_low

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
                    if (trace['action'] == 'dup2') and (trace['file-descriptor'] == fd):
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

    def create_message(self, trace):
        if (trace['level'] == 'taint') and (trace['action'] in ['recv', 'read']):
            if int(trace['return']) >= 0:
                buffer_content = binascii.unhexlify(trace['buffer-content'])
                buffer_addr = int(trace['buffer-address'], 16)
                message = tracemodeler.model.Message(msg_bytes=buffer_content, msg_addr=buffer_addr)
                return message

        return None

    def analyze_net_trace(self, net_trace):
        """ Create message of recv data """
        (message_trace, traces) = (net_trace[0], net_trace[1:])     # Asumme recv trace is in first position
        message = self.create_message(message_trace)

        if message is not None:
            self.fsm.append(message)

            buffer_content = message.bytes
            buffer_addr = message.addr

            """ Write message to memory """
            self.mu.mem_map(self.align_addr(buffer_addr), 4 * 1024 * 1024, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)      # 4 MiB of read page size
            self.mu.mem_write(buffer_addr, buffer_content)

            for trace in traces:
                if trace['action'] == 'compare':
                    if trace['origin'] == 'imm-addr':
                        opcodes = binascii.unhexlify(trace['ins-opcodes'])
                        self.mu.mem_write(self.mu_addr, opcodes)
                        addr = int(trace['addr'], 16)
                        reg = self.get_reg(trace['reg'])
                        self.mu.reg_write(reg, addr)
                        debug.debug(f'{trace["ins-addr"]}: {trace["ins-dis"]}: {trace["action"]}')
                        self.mu.emu_start(self.mu_addr, self.mu_addr + len(opcodes))
                        flags = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)
                    elif trace['origin'] == 'imm-reg':
                        opcodes = binascii.unhexlify(trace['ins-opcodes'])
                        self.mu.mem_write(self.mu_addr, opcodes)
                        debug.debug(f'{trace["ins-addr"]}: {trace["ins-dis"]}: {trace["action"]}')
                        self.mu.emu_start(self.mu_addr, self.mu_addr + len(opcodes))
                        flags = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)
                    else:
                        raise NotImplementedError(f'{trace["action"]}: {trace["ins-dis"]}')
                elif trace['action'] == 'taint-reg':
                    if trace['origin'] == 'addr':
                        opcodes = binascii.unhexlify(trace['ins-opcodes'])
                        self.mu.mem_write(self.mu_addr, opcodes)
                        debug.debug(f'{trace["ins-addr"]}: {trace["ins-dis"]}: {trace["action"]}')
                        try:
                            self.mu.emu_start(self.mu_addr, self.mu_addr + len(opcodes))
                        except unicorn.unicorn.UcError:
                            import pdb; pdb.set_trace()
                elif trace['action'] == 'taint-addr':
                    opcodes = binascii.unhexlify(trace['ins-opcodes'])
                    self.mu.mem_write(self.mu_addr, opcodes)
                    addr = int(trace['addr'], 16)
                    reg = self.get_reg(trace['reg'])
                    self.mu.reg_write(reg, addr)
                    for (region_start, region_end, region_perms) in self.mu.mem_regions():
                        if region_start <= addr <= region_end:
                            break
                    else:
                        self.mu.mem_map(self.align_addr(addr), 4 * 1024 * 1024, perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)      # 4 MiB of write page size
                    debug.debug(f'{trace["ins-addr"]}: {trace["ins-dis"]}: {trace["action"]}')
                    self.mu.emu_start(self.mu_addr, self.mu_addr + len(opcodes))
                elif trace['action'] == 'free-reg':
                    reg = self.get_reg(trace['reg'])
                    self.mu.reg_write(reg, 0x0)
                else:
                    raise NotImplementedError(f'{trace["action"]}: {trace["ins-dis"]}')

    def is_equal(self, flags):
        return (flags & 0x0040) == 1

    def align_addr(self, addr):
        return addr & 0xfffffffff000

    def get_reg(self, reg):
        if reg == 'rax':
            return unicorn.x86_const.UC_X86_REG_RAX
        elif reg == 'r13':
            return unicorn.x86_const.UC_X86_REG_R13

        raise NotImplementedError
