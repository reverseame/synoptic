import os
import shlex
import binascii
import capstone

import tracemodeler.cfg as cfg
import tracemodeler.debug as debug

class Analyzer:
    def __init__(self, arch_mode=capstone.CS_MODE_64):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

    def analyze(self, traces):
        dynamic_cfg = cfg.DynamicCFG()

        for session in self.split_sessions(traces):
            net_traces = self.split_network_activity(session)
            for net_trace in net_traces:
                try:
                    dynamic_cfg.initialize()
                    dynamic_cfg = self.analyze_net_trace(dynamic_cfg, net_trace)
                except cfg.CFGException as e:
                    debug.warning(str(e))
                finally:
                    dynamic_cfg.finalize()

        return dynamic_cfg

    def split_sessions(self, data):
        ret = []

        (index, fd) = (None, None)

        """ Asume there will be always a close call matching the file descriptor of a accept call """
        for (i, trace) in enumerate(data):
            if 'action' in trace:
                if (fd is None) and (trace['action'] == 'accept'):
                    (index, fd) = (i, trace['return'])
                elif fd is not None:
                    """ Duplicate file descriptor """
                    if (trace['action'] == 'dup2') and (trace['file-descriptor'] == fd):
                        fd = trace['return']
                    elif (trace['action'] == 'close') and (fd == trace['file-descriptor']):
                        ret.append(data[index:i])
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

    def analyze_net_trace(self, dynamic_cfg, net_trace):
        print_debug = False
        group = cfg.Group()
        ins = None

        for item in net_trace:
            if not print_debug:
                if 'io-counter' in item:
                    debug.info(f'CFG refinement {item["io-counter"]}...')
                    print_debug = True
            if 'ins-opcodes' in item:
                routine_addr = int(item['routine-addr'], 16)
                routine = item['routine']
                addr = int(item['ins-addr'], 16)
                opcodes = binascii.unhexlify(item['ins-opcodes'])
                dis = next(self.md.disasm(opcodes, addr))           # Just dissasemble one instruction

                """ Get control flow target """
                if item['action'] in ['direct-call', 'indirect-call', 'direct-jmp', 'indirect-jmp', 'ret']:
                    target_addr = int(item['target-addr'], 16)
                    comment = ''
                    if item['action'] in ['direct-call', 'indirect-call']:
                        comment = item['target']
                    ins = cfg.Ins(dis, addr, opcodes, routine=routine, routine_addr=routine_addr, target_addr=target_addr, comment=comment)
                else:
                    ins = cfg.Ins(dis, addr, opcodes, routine=routine, routine_addr=routine_addr)

                if (item['level'] == 'taint') and (item['action'] in ['compare', 'taint-reg', 'taint-addr']):
                        """ Update comment with taint information """
                        ins.update_comment(f'{item["action"].replace("-", " ")} {item["origin"].replace("-", " ")}')
                        ins.tainted = True
                        """ Two or more taint info in the same group means only one taint """
                        group.taint_count = 1

                group.add(ins)

                """ End of group if last ins is either call, ret, or jump """
                if not ins.is_standard():
                    dynamic_cfg.add(group)
                    group = cfg.Group()

        """ Add last group if we finished CFG construction and last instruction is standard """
        if (ins is not None) and (ins.is_standard()):
            dynamic_cfg.add(group)

        return dynamic_cfg
