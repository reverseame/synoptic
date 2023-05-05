import os
import sys
import json
import r2pipe
import binascii
import capstone

import tracemodeler.cfg as cfg
import tracemodeler.debug as debug

class Analyzer:
    def __init__(self, binary=None, arch_mode=capstone.CS_MODE_64):
        self.binary = binary
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

    def analyze(self, traces):
        dynamic_cfg = cfg.DynamicCFG()

        for session in self.split_sessions(traces):
            for net_trace in self.split_network_activity(session):
                try:
                    dynamic_cfg.initialize()
                    dynamic_cfg = self.analyze_net_trace(dynamic_cfg, net_trace)
                except cfg.CFGException as e:
                    debug.warning(str(e))
                finally:
                    dynamic_cfg.finalize()

        binary_base_addr = self.get_base_addr(traces)
        dynamic_cfg = self.analyze_taint_loops(dynamic_cfg, binary_base_addr)

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
                    debug.info(f'Dynamic CFG refinement {item["io-counter"]}...')
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

                """ End group if last ins is either call, ret, or jump """
                if not ins.is_standard():
                    dynamic_cfg.add(group)
                    group = cfg.Group()

        """ Add last group if we finished CFG construction and last instruction is standard """
        if (ins is not None) and (ins.is_standard()):
            dynamic_cfg.add(group)

        return dynamic_cfg

    def get_base_addr(self, traces):
        for trace in traces:
            if trace['action'] == 'relocate':
                return trace['image-low']

    def analyze_taint_loops(self, dynamic_cfg, binary_base_addr):
        function_addrs = ['0x555811ef2020']

        if self.binary is not None:
            for function_addr in function_addrs:
                dynamic_cfg = self.update_function_with_static(dynamic_cfg, binary_base_addr, function_addr)

        return dynamic_cfg

    def update_function_with_static(self, dynamic_cfg, binary_base_addr, function_addr):
        debug.info(f'Updating function at {function_addr} with static information...')

        """ Open binary at base address and close stderr """
        r2 = r2pipe.open(self.binary, flags=['-B', binary_base_addr, '-2'])
        """ Check radare2 version """
        version = r2.cmd('?Vq')
        version = int(version.rstrip().replace('.', ''))
        """ Version below 5.8.4 not supported """
        if version < 584:
            print('radare2 version not supported, please, update your system', file=sys.stderr)
            sys.exit(-1)
        """ Seek to the start of the function """
        r2.cmd(f's {function_addr}')
        """ Define function at current address """
        r2.cmd('af')
        """ List function basic blocks """
        bbs = json.loads(r2.cmd('afbj'))

        nodes = []

        for bb in bbs:
            group = cfg.Group()
            """ Loop every ins addr """
            for ins_addr in bb['instrs']:
                """ Disassemble one instruction """
                ins_info = json.loads(r2.cmd(f'pdj 1 @ {ins_addr}'))[0]
                opcodes = binascii.unhexlify(ins_info["bytes"])
                dis = next(self.md.disasm(opcodes, ins_addr))
                ins = cfg.Ins(dis, ins_addr, opcodes)
                group.add(ins)

            node = cfg.Node(group)
            nodes.append(node)

        r2.quit()

        function_cfg = cfg.CFG()
        function_cfg.nodes = nodes

        for bb in bbs:
            if function_cfg.is_empty():
                node = function_cfg.get_node_by_addr(bb['addr'])
                function_cfg.entry_node = node
                function_cfg.reset_to_node(node)
            self._set_next_nodes(function_cfg, bb)

        function_cfg.export_graph('/tmp/cfg.pdf')

        return dynamic_cfg

    def _set_next_nodes(self, cfg, bb):
        node = cfg.get_node_by_addr(bb['addr'])
        cfg.reset_to_node(node)

        """ Node that ends CFG because does not have ouput tranisitions """
        if bb['outputs'] == 0:
            cfg.finalize()
        elif bb['outputs'] == 1:
            group = cfg.get_node_by_addr(bb['jump']).group
            cfg.add(group)
        elif bb['outputs'] == 2:
            """ Control flow change """
            group = cfg.get_node_by_addr(bb['jump']).group
            cfg.add(group)
            cfg.reset_to_node(node)
            """ Fallthrough """
            group = cfg.get_node_by_addr(bb['fail']).group
            cfg.add(group)
