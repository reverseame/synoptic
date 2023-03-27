import enum
import capstone.x86

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

INS_TYPE_JUMP = 0        # Direct and indirect jump
INS_TYPE_BRANCH = 1      # Conditional jump
INS_TYPE_CALL = 2
INS_TYPE_RETURN = 3
INS_TYPE_STANDARD = 4    # Any other instruction

class Ins:
    def __init__(self, addr, opcodes, dis, optional=''):
        self.addr = addr
        self.opcodes = opcodes
        self.size = len(opcodes)
        self.dis = dis
        self.type = self._get_ins_type(dis)
        self.info = self._get_ins_info(dis)
        self.optional = optional

    def _get_ins_type(self, dis):
        if capstone.x86.X86_GRP_JUMP in dis.groups:
            """ If not jmp instruction, assume is a branch related instruction (conditional jump) """
            if dis.id == capstone.x86.X86_INS_JMP:
                return INS_TYPE_JUMP
            else:
                return INS_TYPE_BRANCH
        elif capstone.x86.X86_GRP_CALL in dis.groups:
            return INS_TYPE_CALL
        elif capstone.x86.X86_GRP_RET in dis.groups:
            return INS_TYPE_RETURN

        return INS_TYPE_STANDARD

    def _get_ins_info(self, dis):
        ret = {}

        if (self.type == INS_TYPE_STANDARD) or (self.type == INS_TYPE_RETURN):
            return ret

        if dis.operands[0].type == capstone.x86.X86_OP_IMM:
            ret['target'] = dis.operands[0].value.imm
            ret['mode'] = 'direct'
        elif dis.operands[0].type == capstone.x86.X86_OP_MEM:
            ret['target'] = 'unknown'
            ret['mode'] = 'indirect'
        else:
            raise NotImplementedError(f'{dis.mnemonic} {dis.op_str}\t: Ins not supported')

        if (self.type == INS_TYPE_BRANCH) or (self.type == INS_TYPE_CALL):
            ret['fallthrough'] = self.addr + self.size

        return ret

    def __eq__(self, other):
        if isinstance(other, Ins):
            return (self.addr == other.addr) and (self.opcodes == other.opcodes)

        return False

    def __str__(self):
        string = f'{hex(self.addr)} {[self.size]}: {self.dis.mnemonic} {self.dis.op_str}'

        if self.optional:
            string += f'({self.optional})'

        return string

class Group:
    def __init__(self):
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
        self.tainted = (self.tainted or node.tainted)

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
        self.entry = None
        self.index = None
        self.last = set()
        self.last_inserted = None

    def is_empty(self):
        return self.entry is None

    def initialize(self):
        if not self.is_empty():
            self.index = self.entry

    def finalize(self):
        if not self.is_empty():
            self.last.add(self.last_inserted)

    def add(self, group):
        node = Node(group)

        if self.is_empty():
            self.entry = node
            self.index = self.entry
            self.last_inserted = self.entry
        else:
            """
            This node already have edges defines, so we need to check if the new
            node is alreay defined
            """
            if self.index.edges:
                """
                If index is equal to incomming node, do nothing. Otherwise,
                check transition
                """
                if self.index != node:
                    for edge in self.index:
                        """ Check if transition is alreay defined and cosume its destination """
                        if edge.dst == node:
                            edge.count += 1
                            self.index = edge.dst
                            """ Keep taint info """
                            self.index.taint(node)
                            break
                    else:
                        """ Check if edge dst is alreay defined and set transition to that node """
                        node_found = None
                        pending_edges = [(self.index, self.index.edges)]
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
                            self.index.edges.append(new_edge)
                            self.index = node
                            self.last_inserted = node
                        else:
                            new_edge = Edge(node_found)
                            self.index.edges.append(new_edge)
                            self.index = node_found
                            self.index.taint(node)
                            self.last_inserted = node_found
            else:
                new_edge = Edge(node)
                self.index.edges.append(new_edge)
                self.index = node
                self.last_inserted = node

    def export_graph(self, output):
        graph = graphviz.Digraph(output)

        """ General CFG Style """
        graph.attr('node', shape='box', fontname='monospace')
        graph.attr('edge', fontname='monospace')

        """ CFG first transition """
        graph.node('entry', label='', shape='circle', style='filled', color='black', fixedsize='true')

        """ CFG node style """
        entry_node_id = hex(self.entry.group.leader.addr)
        label = '\l'.join([str(ins) for ins in self.entry.group.inss]) + '\l'

        if self.entry.tainted:
            graph.node(entry_node_id, label=label, style='filled', fillcolor='lightblue')
        else:
            graph.node(entry_node_id, label=label)

        graph.edge('entry', entry_node_id)


        """ Iterate """
        node = self.entry
        pending_edges = [(node, node.edges)]
        already_seen =  []
        
        while pending_edges:
            (node, edges) = pending_edges.pop(0)    # Get first tuple
            for edge in edges:
                node_id = hex(node.group.leader.addr)
                edge_node_id = hex(edge.dst.group.leader.addr)

                if (node_id, edge_node_id) not in already_seen:
                    label = '\l'.join([str(ins) for ins in edge.dst.group.inss]) + '\l'     # '\l' means left-aligned, last one is mandatory to ensure alignment of label last line
                    if edge.dst.tainted:
                        graph.node(edge_node_id, label=label, style='filled', fillcolor='lightblue')
                    else:
                        graph.node(edge_node_id, label=label)
                    graph.edge(node_id, edge_node_id, label=str(edge.count))
                    already_seen.append((node_id, edge_node_id))

                new_edges = (edge.dst, edge.dst.edges)
                pending_edges.append(new_edges)

        """ CFG last transition """
        graph.node('final', label='', shape='doublecircle', style='filled', color='black', fixedsize='true')

        for last_node in self.last:
            last_node_id = hex(last_node.group.leader.addr)
            graph.edge(last_node_id, 'final', color='lightcoral')
            graph.node(last_node_id, style='filled', fillcolor='lightcoral')

        """ Generate Graphviz DOT file (.gv) """
        graph.render()
