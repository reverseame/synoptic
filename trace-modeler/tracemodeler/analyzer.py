import os
import sys
import json
import r2pipe
import binascii
import capstone

import tracemodeler.cfg as cfg
import tracemodeler.debug as debug
import tracemodeler.utils as utils
import tracemodeler.symbolic as symbolic

class Analyzer:
    def __init__(self, binary, symbolic_engine, arch_mode=capstone.CS_MODE_64):
        self.binary = binary
        self.symbolic_engine = symbolic.SymbolicEngine(symbolic_engine, binary)
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
                    ins = cfg.Ins(dis, addr, opcodes, routine=routine, routine_addr=routine_addr, target_addr=target_addr, comment=comment, trace=item)
                else:
                    ins = cfg.Ins(dis, addr, opcodes, routine=routine, routine_addr=routine_addr, trace=item)

                if (item['level'] == 'taint') and (item['action'] in ['compare', 'taint-reg', 'taint-addr', 'free-addr']):
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
                return int(trace['image-low'], 0)

    def analyze_tainted_loops(self, dynamic_cfg, binary_base_addr):
        tainted_cfgs = dynamic_cfg.get_tainted_cfgs()

        debug.info(f'Opening {os.path.basename(self.binary)} with radare2...')
        """ Open binary at base address and close stderr """
        r2 = r2pipe.open(self.binary, flags=['-B', hex(binary_base_addr), '-2'])

        for tainted_cfg in tainted_cfgs:
            loop_info = tainted_cfg.get_tainted_loop_info()
            if loop_info:
                try:
                    self.update_cfg_with_static_info(r2, tainted_cfg)
                except cfg.CFGException as e:
                    debug.warning(f'{str(e)}\t: Couldn\'t update {hex(tainted_cfg.id)} ({tainted_cfg.entry_node.group.leader.routine}) with static information')

                self.get_symbolic_messages(binary_base_addr, tainted_cfg, loop_info)

        r2.quit()

    def update_cfg_with_static_info(self, r2, tainted_cfg):
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

        static_nodes = []
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

            static_node = cfg.Node(group, static=True)
            static_nodes.append(static_node)

        """ Add static_node if is not already defined in the CFG """
        for static_node in static_nodes:
            if static_nodes not in tainted_cfg:
                tainted_cfg.nodes.append(static_node)

        """ Set all static transitions based in r2 basic blocks information """
        self._set_static_transitions(tainted_cfg, bbs)

    def _set_static_transitions(self, cfg, bbs):
        for bb in bbs:
            """ Each basic block has several ouput transitions """
            node = cfg.get_node_by_addr(bb['addr'])
            """ Get node fallthrough in case of node ending in a call ins """
            if node.group.tail.is_call():
                node = cfg.get_node_by_addr(node.group.tail.info['fallthrough'])
            cfg.reset_to_node(node)

            """ Node that ends CFG because does not have output tranisitions """
            if bb['outputs'] == 0:
                if node.static:
                    cfg.finalize()
            elif bb['outputs'] == 1:
                defined_node = cfg.get_node_by_addr(bb['jump'])
                if defined_node.static:
                    cfg.add(defined_node.group)
            elif bb['outputs'] == 2:
                """ Control flow change """
                defined_node = cfg.get_node_by_addr(bb['jump'])
                if defined_node.static:
                    cfg.add(defined_node.group)
                """ Reset to node containing two outputs """
                cfg.reset_to_node(node)
                """ Fallthrough """
                defined_node = cfg.get_node_by_addr(bb['fail'])
                if defined_node.static:
                    cfg.add(defined_node.group)

    def get_symbolic_messages(self, binary_base_addr, target_cfg, loop_info):
        debug.info(f'Symbolic\t: Setting up symbolic information for {hex(target_cfg.id)} ({target_cfg.entry_node.group.leader.routine})...')

        if target_cfg.id == 0x563547a94020:
            import pdb; pdb.set_trace()
            self.symbolic_engine.open_binary(base_addr=binary_base_addr)

            for loop in loop_info:
                if 'pre-header' in loop:
                    start_node = loop['pre-header']
                else:
                    start_node = loop['header']

                start_addr = start_node.id                
                debug.info(f'Symbolic\t: start-addr\t: {hex(start_addr)}')
                self.symbolic_engine.set_start_addr(start_addr)
                self._analyze_symbolic_vars(start_node)
                self._analyze_target_addrs(target_cfg)
                results = self.symbolic_engine.run()

                if results:
                    for result in results:
                        debug.info(f'Result found: {result}')
                else:
                    debug.warning('Unable to find symbolic values')

    def _analyze_symbolic_vars(self, node):
        """ Loop every ins in node """
        for ins in node.group:
            if ins.tainted:
                """ mov reg, [reg] """
                if (ins.trace['action'] == 'taint-reg') and (ins.trace['origin'] == 'from-addr'):
                    operand = ins.dis.operands[1]
                    if operand.type == capstone.x86.X86_OP_MEM:
                        tainted_reg_id = operand.mem.base
                        tainted_reg_name = ins.dis.reg_name(tainted_reg_id)
                        debug.info(f'Symbolic\t: buffer\t: {tainted_reg_name}')
                        self.symbolic_engine.symbolic_buffer(tainted_reg_id, tainted_reg_name)

    def _analyze_target_addrs(self, target_cfg):
        final_nodes = set(target_cfg.final_nodes)

        while final_nodes:
            node = final_nodes.pop()

            if node.static:
                debug.info(f'Symbolic\t: cut-addr\t: {hex(node.id)}')
                self.symbolic_engine.set_cut_addr(node.id)
            else:
                debug.info(f'Symbolic\t: goal-addr\t: {hex(node.id)}')
                self.symbolic_engine.set_goal_addr(node.id)
