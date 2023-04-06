import os
import PyPDF2
import capstone.x86
import tempfile

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

INS_TYPE_JUMP = 0        # Direct and indirect jump
INS_TYPE_BRANCH = 1      # Conditional jump
INS_TYPE_CALL = 2
INS_TYPE_RETURN = 3
INS_TYPE_STANDARD = 4    # Any other instruction

""" Capstone Dissasembler """
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

class Ins:
    def __init__(self, addr, opcodes, tainted=False, routine='', comment=''):
        self.addr = addr
        self.opcodes = opcodes
        self.size = len(opcodes)
        self.dis = next(md.disasm(opcodes, addr))                # Just dissasemble one instruction
        self.tainted = tainted
        self.type = self._get_ins_type()
        self.info = self._get_ins_info()
        self.routine = routine
        self.comment = comment

    def _get_ins_type(self):
        if capstone.x86.X86_GRP_JUMP in self.dis.groups:
            """ If not jmp instruction, assume is a branch related instruction (conditional jump) """
            if self.dis.id == capstone.x86.X86_INS_JMP:
                return INS_TYPE_JUMP
            else:
                return INS_TYPE_BRANCH
        elif capstone.x86.X86_GRP_CALL in self.dis.groups:
            return INS_TYPE_CALL
        elif capstone.x86.X86_GRP_RET in self.dis.groups:
            return INS_TYPE_RETURN

        return INS_TYPE_STANDARD

    def _get_ins_info(self):
        ret = {}

        if (self.type == INS_TYPE_STANDARD) or (self.type == INS_TYPE_RETURN):
            return ret

        if self.dis.operands[0].type == capstone.x86.X86_OP_IMM:
            ret['target'] = self.dis.operands[0].value.imm
            ret['mode'] = 'direct'
        elif self.dis.operands[0].type == capstone.x86.X86_OP_MEM:
            ret['target'] = 'unknown'
            ret['mode'] = 'indirect'
        else:
            raise NotImplementedError(f'{self.dis.mnemonic} {self.dis.op_str}\t: Ins not supported')

        if (self.type == INS_TYPE_BRANCH) or (self.type == INS_TYPE_CALL):
            ret['fallthrough'] = self.addr + self.size

        return ret

    def is_call(self):
        return self.type == INS_TYPE_CALL

    def is_return(self):
        return self.type == INS_TYPE_RETURN

    def is_jump(self):
        return self.type == INS_TYPE_JUMP

    def is_branch(self):
        return self.type == INS_TYPE_BRANCH

    def is_plt_jmp(self):
        """ Assume any `jmp qword ptr [rip]` as plt jump """
        if self.is_jump():
            if self.dis.operands[0].type == capstone.x86.X86_OP_MEM:
                return self.dis.operands[0].value.mem.base == capstone.x86.X86_REG_RIP

        return False

    def is_standard(self):
        return self.type == INS_TYPE_STANDARD

    def is_control_flow(self):
        return self.is_return() or self.is_call()

    def dumps(self, opcodes_padding=0):
        tab_padding = ' ' * 5

        string = f'{hex(self.addr)}{tab_padding}{self.opcodes.hex().ljust(opcodes_padding)}{tab_padding}{self.dis.mnemonic} {self.dis.op_str}'

        if self.comment:
            string += f'{tab_padding}; {self.comment}'

        return string

    def __str__(self):
        return self.dumps()

    def __eq__(self, other):
        if isinstance(other, Ins):
            return (self.addr == other.addr) and (self.opcodes == other.opcodes)

        return False

class Group:
    def __init__(self, routine=''):
        self.routine = routine
        self.inss = []
        self.leader = None
        self.tail = None
        self.tainted = False

    def add(self, ins):
        if self.leader is None:
            self.leader = ins

        self.tail = ins

        self.inss.append(ins)

    def __str__(self):
        return '\n'.join([str(ins) for ins in self.inss])

    def __len__(self):
        return len(self.inss)

    def __iter__(self):
        for ins in self.inss:
            yield ins

    def __eq__(self, other):
        if isinstance(other, Group):
            if len(self) == len(other):
                return all([ins == ins_other for (ins, ins_other) in zip(self, other)])

        return False

class Edge:
    def __init__(self, dst):
        self.dst = dst
        self.count = 1

    def __eq__(self, other):
        if isinstance(other, Edge):
            return self.dst == other.dst

        return False

class Node:
    def __init__(self, group):
        self.group = group
        self.tainted = group.tainted
        self.edges = []

    def taint(self, node):
        """ Preserve if node was tainted at some time """
        self.tainted = self.tainted or node.tainted

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.group == other.group

        return False

    def __str__(self):
        return str(self.group)

    def __iter__(self):
        for edge in self.edges:
            yield edge

    def __hash__(self):
        return self.group.leader.addr

class CFG:
    def __init__(self):
        self.entry_node = None
        self.index_node = None
        self.last_nodes = set()
        self.last_inserted = None
        self.tainted = False
        self.next = set()
        self.previous = None

    def taint(self, node):
        """ Preserve if one of nodes was tainted at some time """
        self.tainted = self.tainted or node.tainted

    def is_empty(self):
        return self.entry_node is None

    def initialize(self):
        if not self.is_empty():
            self.index_node = self.entry_node

    def finalize(self):
        if not self.is_empty():
            self.last_nodes.add(self.last_inserted)

    def add(self, group):
        node = Node(group)

        if self.is_empty():
            self.entry_node = node
            self.index_node = self.entry_node
            self.last_inserted = self.entry_node
        else:
            """
            This node already have edges defines, so we need to check if the new
            node is alreay defined
            """
            if self.index_node.edges:
                """
                If index is equal to incomming node, do nothing. Otherwise,
                check transition
                """
                if self.index_node != node:
                    for edge in self.index_node:
                        """ Check if transition is alreay defined and cosume its destination """
                        if edge.dst == node:
                            edge.count += 1
                            self.index_node = edge.dst
                            """ Keep taint info """
                            self.index_node.taint(node)
                            self.taint(node)
                            self.last_inserted = index_node
                            break
                    else:
                        """ Check if edge dst is alreay defined and set transition to that node """
                        node_found = None
                        pending_edges = [(self.index_node, self.index_node.edges)]
                        already_seen =  []
                        
                        while (len(pending_edges) > 0) and (node_found is None):
                            (n, edges) = pending_edges.pop(0)
                            for edge in edges:
                                if edge.dst == node:
                                    node_found = edge.dst
                                    break
                                node_id = hex(n.group.leader.addr)
                                edge_node_id = hex(edge.dst.group.leader.addr)
                                if (node_id, edge_node_id) not in already_seen:
                                    already_seen.append((node_id, edge_node_id))

                                new_edges = (edge.dst, edge.dst.edges)
                                pending_edges.append(new_edges)

                        if node_found is None:
                            """ Add a new one if not alreay defined """
                            new_edge = Edge(node)
                            self.index_node.edges.append(new_edge)
                            self.index_node = node
                            self.last_inserted = node
                        else:
                            new_edge = Edge(node_found)
                            self.index_node.edges.append(new_edge)
                            self.index_node = node_found
                            self.index_node.taint(node)
                            self.taint(node)
                            self.last_inserted = node_found
            else:
                new_edge = Edge(node)
                self.index_node.edges.append(new_edge)
                self.index_node = node
                self.last_inserted = node

    def __hash__(self):
        return self.entry_node.group.leader.addr

    def __eq__(self, other):
        if isinstance(other, CFG):
            return hash(self) == hash(other)

        return False

class DynamicCFG:
    def __init__(self):
        self.entry_cfg = None
        self.index_cfg = None
        self.last_cfg = None

    def is_empty(self):
        return self.entry_cfg is None

    def add(self, group):
        if self.is_empty():
            cfg = CFG()
            cfg.add(group)
            self.entry_cfg = cfg
            self.index_cfg = self.entry_cfg
            self.last_cfg = self.entry_cfg
        else:
            """ Create a new CFG because last inserted group was a call function """
            if self.index_cfg.last_inserted.group.tail.is_call():
                """ call followed by plt jmp, fallthrough to the previous CFG """
                if group.tail.is_plt_jmp():
                    self.index_cfg.add(group)
                else:
                    cfg = CFG()
                    cfg.add(group)
                    temp = self.index_cfg
                    self.index_cfg.next.add(cfg)
                    self.index_cfg = cfg
                    self.index_cfg.previous = temp
                    self.last_cfg = cfg
                    """ Go to the previous CFG if return instruction """
            elif self.index_cfg.last_inserted.group.tail.is_return():
                """
                First CFG usually is in the middle of a function, so return
                instruction does not return to another CFG yet
                """
                if self.entry_cfg == self.index_cfg:
                    cfg = CFG()
                    cfg.add(group)
                    temp = self.index_cfg
                    self.index_cfg.next.add(cfg)
                    self.index_cfg = cfg
                    self.index_cfg.previous = temp
                    self.last_cfg = cfg
                else:
                    """ Return to previous CFG """
                    self.index_cfg = self.index_cfg.previous
                    self.index_cfg.add(group)
            else:
                self.index_cfg.add(group)

    def initialize(self):
        if not self.is_empty():
            self.index_cfg = self.entry_cfg

    def finalize(self):
        if not self.is_empty():
            self.last_cfg.finalize()

    def _export_cfg(self, cfg, cfg_output_filename, first=False):
        graph = graphviz.Digraph(cfg_output_filename)

        """ General CFG Style """
        graph.attr('node', shape='box', fontname='monospace')
        graph.attr('edge', fontname='monospace')

        """ CFG first transition """
        if first:
            graph.node('entry', label='', shape='circle', style='filled', color='black', fixedsize='true')

        """ CFG node style """
        entry_node_id = hex(cfg.entry_node.group.leader.addr)
        padding = max([len(ins.opcodes.hex()) for ins in cfg.entry_node.group.inss])
        label = '; ' + cfg.entry_node.group.leader.routine + '\l\l' + '\l'.join([ins.dumps(padding) for ins in cfg.entry_node.group.inss]) + '\l'     # '\l' means left-aligned, last one is mandatory to ensure alignment of label last line

        if cfg.entry_node.tainted:
            graph.node(entry_node_id, label=label, style='filled', fillcolor='lightblue')
        else:
            graph.node(entry_node_id, label=label)

        if first:
            graph.edge('entry', entry_node_id)


        """ Iterate """
        node = cfg.entry_node
        pending_edges = [(node, node.edges)]
        already_seen =  []
        
        while pending_edges:
            (node, edges) = pending_edges.pop(0)    # Get first tuple
            for edge in edges:
                node_id = hex(node.group.leader.addr)
                edge_node_id = hex(edge.dst.group.leader.addr)

                if (node_id, edge_node_id) not in already_seen:
                    padding = max([len(ins.opcodes.hex()) for ins in edge.dst.group.inss])
                    label = '; ' + edge.dst.group.leader.routine + '\l\l' + '\l'.join([ins.dumps(padding) for ins in edge.dst.group.inss]) + '\l'     # '\l' means left-aligned, last one is mandatory to ensure alignment of label last line
                    if edge.dst.tainted:
                        graph.node(edge_node_id, label=label, style='filled', fillcolor='lightblue')
                    else:
                        graph.node(edge_node_id, label=label)
                    graph.edge(node_id, edge_node_id, label=str(edge.count))
                    already_seen.append((node_id, edge_node_id))

                    """if edge.dst.group.tail.is_call():
                        import pdb; pdb.set_trace()"""

                new_edges = (edge.dst, edge.dst.edges)
                pending_edges.append(new_edges)

        """ CFG last transition """
        if len(cfg.last_nodes):
            graph.node('final', label='', shape='doublecircle', style='filled', color='black', fixedsize='true')

            for last_node in cfg.last_nodes:
                last_node_id = hex(last_node.group.leader.addr)
                graph.edge(last_node_id, 'final', color='lightcoral')
                graph.node(last_node_id, style='filled', fillcolor='lightcoral')

        """ Generate Graphviz DOT file (.gv) """
        graph.render()

    def export_graph(self, output):
        filenames = []

        with tempfile.TemporaryDirectory() as temp_dir:
            pending_cfgs = []
            cfg = self.entry_cfg
            cfg_output_filename = os.path.join(temp_dir, hex(hash(cfg)))
            self._export_cfg(cfg, cfg_output_filename, first=True)
            filenames.append(cfg_output_filename)
            pending_cfgs.extend(list(cfg.next))

            while pending_cfgs:
                cfg = pending_cfgs.pop(0)
                cfg_output_filename = os.path.join(temp_dir, hex(hash(cfg)))
                if cfg_output_filename not in filenames:
                    self._export_cfg(cfg, cfg_output_filename)
                    filenames.append(cfg_output_filename)
                pending_cfgs.extend(list(cfg.next))

            """ Join temp files """
            merger = PyPDF2.PdfMerger()
            for filename in filenames:
                merger.append(f'{filename}.gv.pdf')

            merger.write(output)
            merger.close()
