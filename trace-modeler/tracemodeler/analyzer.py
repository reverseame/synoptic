import os
import sys
import json
import r2pipe
import binascii
import capstone

import tracemodeler.cfg as cfg
import tracemodeler.debug as debug
import tracemodeler.utils as utils

class Analyzer:
    def __init__(self, binary=None, arch_mode=capstone.CS_MODE_64):
        self.binary = binary
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

    def analyze(self, traces):
        dynamic_cfg = cfg.DynamicCFG()

        for session in self.split_sessions(traces):
            for (i, net_trace) in enumerate(self.split_network_activity(session)):
                try:
                    dynamic_cfg.initialize()
                    dynamic_cfg = self.analyze_net_trace(dynamic_cfg, net_trace)
                except cfg.CFGException as e:
                    debug.warning(str(e))
                finally:
                    dynamic_cfg.finalize()

        binary_base_addr = self.get_base_addr(traces)
        self.analyze_tainted_loops(dynamic_cfg, binary_base_addr)

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

    def analyze_tainted_loops(self, dynamic_cfg, binary_base_addr):
        tainted_cfgs = dynamic_cfg.get_tainted_cfgs()

        if self.binary is not None:
            r2 = self._open_radare2(binary_base_addr)

        for tainted_cfg in tainted_cfgs:
            if tainted_cfg.contains_tainted_loop():
                target_cfg = tainted_cfg
                if self.binary is not None:
                    target_cfg = self.update_cfg_with_static(r2, tainted_cfg)
                """ Create .ini file for Binsec symbolic execution """
                self.create_binsec_file(target_cfg)

        if self.binary is not None:
            r2.quit()

    def _open_radare2(self, binary_base_addr):
        debug.info(f'Opening {os.path.basename(self.binary)} with radare2...')
        """ Open binary at base address and close stderr """
        r2 = r2pipe.open(self.binary, flags=['-B', binary_base_addr, '-2'])
        """ Check radare2 version """
        version_str = r2.cmd('?Vq').rstrip()

        """ Transform '5.8.4' into 584 """
        min_r2_supported = int(utils.MIN_R2_VERSION.replace('.', ''))
        version = int(version_str.replace('.', ''))
        if version < min_r2_supported:
            r2.quit()
            debug.error(f'radare2 version found ({version_str}) older than minimun supported ({utils.MIN_R2_VERSION})')
            sys.exit(-1)

        return r2

    def update_cfg_with_static(self, r2, tainted_cfg):
        """ Function address pointed by ins leader of the entry node """
        function_name = tainted_cfg.entry_node.group.leader.routine
        function_addr = hex(tainted_cfg.entry_node.group.leader.routine_addr)

        debug.info(f'Updating function at {function_addr} ({function_name}) with static information...')

        """ Seek to the start of the function """
        r2.cmd(f's {function_addr}')
        """ Define function at current address """
        r2.cmd('af')
        """ List function basic blocks """
        bbs = json.loads(r2.cmd('afbj'))

        nodes = []
        routine = ''
        routine_addr = 0

        """ Create CFG groups based in basic block information """
        for bb in bbs:
            group = cfg.Group()
            """ Loop every ins addr in basic block """
            for ins_addr in bb['instrs']:
                """ Disassemble one instruction """
                ins_info = json.loads(r2.cmd(f'pdj 1 @ {ins_addr}'))[0]
                opcodes = binascii.unhexlify(ins_info["bytes"])
                dis = next(self.md.disasm(opcodes, ins_addr))
                """ Get routine name, only in the first ins """
                if not routine:
                    routine = ins_info['flags'][0]
                    routine_addr = ins_info['fcn_addr']
                ins = cfg.Ins(dis, ins_addr, opcodes, routine=routine, routine_addr=routine_addr)
                group.add(ins)

            node = cfg.Node(group)
            nodes.append(node)

        """ Create CFG and define all its nodes without transitions """
        function_cfg = cfg.CFG()
        function_cfg.nodes = nodes

        """ Set transitions based in basic blocks """
        for bb in bbs:
            if function_cfg.is_empty():
                node = function_cfg.get_node_by_addr(bb['addr'])
                function_cfg.entry_node = node
                function_cfg.reset_to_node(node)
            self._set_next_nodes(function_cfg, bb)

        output = f'/tmp/func-{function_addr}'
        function_cfg.export_graph(output)
        debug.debug(f'{output}.gv.pdf saved')

        return tainted_cfg

    def _set_next_nodes(self, cfg, bb):
        """ Each basic block has several ouput transitions """
        node = cfg.get_node_by_addr(bb['addr'])
        cfg.reset_to_node(node)

        """ Node that ends CFG because does not have output tranisitions """
        if bb['outputs'] == 0:
            cfg.finalize()
        elif bb['outputs'] == 1:
            group = cfg.get_node_by_addr(bb['jump']).group
            cfg.add(group)
        elif bb['outputs'] == 2:
            """ Control flow change """
            group = cfg.get_node_by_addr(bb['jump']).group
            cfg.add(group)
            """ Reset to node containing two outputs """
            cfg.reset_to_node(node)
            """ Fallthrough """
            group = cfg.get_node_by_addr(bb['fail']).group
            cfg.add(group)

    def create_binsec_file(self, target_cfg):
        debug.warning(f'Binsec file for {hex(target_cfg.entry_node.group.leader.routine_addr)} ({target_cfg.entry_node.group.leader.routine}) not created')
