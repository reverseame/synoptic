import os
import sys
import json
import r2pipe
import string
import struct
import binascii
import capstone
import collections

import tracemodeler.cfg as cfg
import tracemodeler.fsm
import tracemodeler.debug as debug
import tracemodeler.utils as utils
import tracemodeler.symbolic as symbolic

class Model:
    def __init__(self, arch_mode=capstone.CS_MODE_64):
        self.fsm = tracemodeler.fsm.ProtocolFSM()
        self.cfg = tracemodeler.cfg.DynamicCFG()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        self.md.detail = True

    def analyze(self, traces):
        debug.info('CFG analysis...')
        self.cfg_analysis(traces)
        debug.info('FSM analysis...')
        self.fsm_analysis(traces)

    def cfg_analysis(self, traces):
        for session in self.split_sessions(traces):
            for net_trace in self.split_network_activity(session):
                try:
                    self.cfg.initialize()
                    self.analyze_cfg_net_trace(net_trace)
                except cfg.CFGException as e:
                    debug.warning(str(e))
                finally:
                    self.cfg.finalize()

    def fsm_analysis(self, traces):
        self.fsm.initialize()

        buffer_comparations = self.get_buffer_comparations(traces)
        (self.fsm.textual, self.fsm.delimiters) = self.get_delimiters(buffer_comparations)

        for item in buffer_comparations:
            message = tracemodeler.fsm.Message(item['buffer'])
            message.analyze_keyword(self.fsm.delimiters, self.fsm.textual)
            message.analyze_structure(self.fsm.delimiters)
            self.fsm.add(message)

    def analyze_cfg_net_trace(self, net_trace):
        print_debug = False
        group = cfg.Group()
        ins = None
        signal_detected = False

        for item in net_trace:
            if not print_debug:
                if 'io-counter' in item:
                    debug.debug(f'Dynamic CFG refinement {item["io-counter"]}...')
                    print_debug = True

            if item['action'] == 'signal-detected':
                signal_detected = True
            elif item['action'] == 'signal-finished':
                signal_detected = False

            """ Only create a new instruction if we are not in a signal """
            if ('ins-opcodes' in item) and not signal_detected:
                routine_addr = int(item['routine-addr'], 16)
                routine = item['routine']
                addr = int(item['ins-addr'], 16)
                opcodes = binascii.unhexlify(item['ins-opcodes'])
                dis = next(self.md.disasm(opcodes, addr))           # Just dissasemble one instruction

                """ Get control flow target """
                if item['action'] in ['direct-call', 'indirect-call', 'direct-jump', 'indirect-jump', 'ret']:
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
                    self.cfg.add(group)
                    group = cfg.Group()

        """ Add last group if we finished CFG construction and last instruction is standard """
        if (ins is not None) and (ins.is_standard()):
            self.cfg.add(group)

    def get_buffer_comparations(self, traces):
        ret = []

        for session in self.split_sessions(traces):
            for net_trace in self.split_network_activity(session):
                buffer = {}
                comparations = []
                for item in net_trace:
                    if item['level'] == 'taint':
                        if item['action'] in ['recv', 'read']:
                            buffer['buffer'] = binascii.unhexlify(item['buffer-content'])
                        elif item['action'] == 'compare':
                            if ((item['origin'] == 'reg-to-reg') and (item['reg1'] != item['reg2'])) or (item['origin'] != 'reg-to-reg'):
                                comparations.append(item)
                if comparations: buffer['comparations'] = comparations
                if buffer: ret.append(buffer)

        return ret

    def get_delimiters(self, buffer_comparations):
        ret = []
        textual = False

        all_comparations = []
        [all_comparations.extend(item['comparations']) for item in buffer_comparations]
        all_buffers = [item['buffer'] for item in buffer_comparations]

        """ Check for the count of all imm comparations """
        count = collections.Counter([item['imm'] for item in all_comparations if item['origin'] in ['addr-to-imm', 'reg-to-imm']])

        """ Textual protocol """
        if all([self.is_printable(buffer) for buffer in all_buffers]):
            textual = True
            for char in count.keys():
                try:
                    byte_char = struct.pack('=B', int(char, 0))
                    """ If character is in any of the buffers, we considered it a delimiter """
                    if any([byte_char in buffer for buffer in all_buffers]):
                        if byte_char not in ret:
                            ret.append(byte_char)
                except struct.error:
                    pass
        else:
            raise NotImplementedError('Binary protocol not implemented')

        return (textual, ret)

    def is_printable(self, buffer):
        decoded = buffer.decode('utf-8')
        return all([char in string.printable for char in decoded])

    def get_keyword(self, buffer, delimiters, textual=False):
        if textual:
            """ Strip special chars at the end """
            buffer = buffer.decode('utf-8').rstrip()

        for delimiter in delimiters:
            """
            Assume that a delimiter at the end of buffer does not correspond to
            keyword delimitation, only as buffer termination
            """
            if (delimiter in buffer) and (delimiter != buffer[-1]):
                byte = delimiters[0]
                keyword = buffer.split(byte)[0]
                return keyword

        """ No delimeters found, return same buffer """
        return buffer

    def symbolic_analysis(self, traces, binary, symbolic_engine):
        symbolic_engine = symbolic.SymbolicEngine(symbolic_engine, binary)
        binary_base_addr = self.get_base_addr(traces)
        results = self._symbolic_analysis(binary, symbolic_engine, binary_base_addr)
        self.analyze_buffers(results)

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

    def get_base_addr(self, traces):
        for trace in traces:
            if trace['action'] == 'relocate':
                return int(trace['image-low'], 0)

    def _symbolic_analysis(self, binary, symbolic_engine, binary_base_addr):
        ret = []
        tainted_cfgs = self.cfg.get_tainted_cfgs()

        debug.info(f'Opening {os.path.realpath(binary)} with radare2...')
        """ Open binary at base address and close stderr """
        r2 = r2pipe.open(binary, flags=['-B', hex(binary_base_addr), '-2'])

        for tainted_cfg in tainted_cfgs:
            loop_info = tainted_cfg.get_tainted_loop_info()
            if loop_info:
                try:
                    self.update_cfg_with_static_info(r2, tainted_cfg)
                except cfg.CFGException as e:
                    debug.warning(f'{str(e)}\t: Couldn\'t update {hex(tainted_cfg.id)} ({tainted_cfg.entry_node.group.leader.routine}) with static information')

                result = self.get_symbolic_buffers(symbolic_engine, binary_base_addr, tainted_cfg, loop_info)
                debug.info(f'{len(result)} concrete buffers found by symbolic execution')
                ret.append(result)

        r2.quit()

        return ret

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

    def get_symbolic_buffers(self, symbolic_engine, binary_base_addr, target_cfg, loop_info):
        ret = []

        debug.info(f'Symbolic\t: Setting up symbolic information for {hex(target_cfg.id)} ({target_cfg.entry_node.group.leader.routine})...')

        symbolic_engine.open_binary(base_addr=binary_base_addr)

        for loop in loop_info:
            if 'pre-header' in loop:
                start_node = loop['pre-header']
            else:
                start_node = loop['header']

            start_addr = start_node.id                
            debug.info(f'Symbolic\t: start-addr\t: {hex(start_addr)}')
            symbolic_engine.start(start_addr)
            self._analyze_symbolic_vars(symbolic_engine, start_node)
            self._analyze_target_addrs(symbolic_engine, target_cfg)

            already_seen_count = 0
            already_seen_threshold = 5

            for results in symbolic_engine.run():
                """ Stop symbolic execution if we do not encounter new buffers """
                if already_seen_count >= already_seen_threshold:
                    debug.warning('We are obtaining the same concrete buffers, skipping...')
                    return ret

                result = results[0]
                if result in ret:
                    already_seen_count += 1
                else:
                    already_seen_count = 0
                    ret.append(result)

        return ret

    def _analyze_symbolic_vars(self, symbolic_engine, node):
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
                        symbolic_engine.symbolic_buffer(tainted_reg_id, tainted_reg_name)

    def _analyze_target_addrs(self, symbolic_engine, target_cfg):
        final_nodes = set(target_cfg.final_nodes)

        while final_nodes:
            node = final_nodes.pop()

            if node.static:
                debug.info(f'Symbolic\t: cut-addr\t: {hex(node.id)}')
                symbolic_engine.cut(node.id)
            else:
                debug.info(f'Symbolic\t: goal-addr\t: {hex(node.id)}')
                symbolic_engine.goal(node.id)

    def analyze_buffers(self, buffers):
        """ Order buffers by length """
        buffers = sorted(buffers, key=lambda x: len(x), reverse=True)

        """ Assume that keywords are contained in the list with more results """
        keywords = buffers[0]

        """ Strip trailing zeros in buffer """
        keywords = [self.strip_buffer(keyword, self.fsm.textual) for keyword in keywords]

        if self.fsm.textual:
            """ Any keyword not previously found could be a new keyword """
            new_keywords = [keyword.upper() for keyword in keywords if keyword.upper() not in [fsm_keyword.upper() for fsm_keyword in self.fsm.keywords]]
            """ Ensure that at least one of the inferred keywords is in the previous known keywords """
            if new_keywords and any([keyword.upper() in [fsm_keyword.upper() for fsm_keyword in self.fsm.keywords] for keyword in keywords]):
                debug.info(f'{len(new_keywords)} keywords inferred: {new_keywords}')
                self.fsm.inferred_keywords.extend(new_keywords)
            else:
                debug.warning(f'Unable to find new keywords in {keywords}')
        else:
            raise NotImplementedError

    def strip_buffer(self, buffer, textual):
        ret = buffer

        if textual:
            """
            A null byte in a textual protocol is not valid, so remove trailing
            bytes after first occurrence
            """
            if b'\x00' in buffer:
                ret = buffer.split(b'\x00')[0]

        return ret
