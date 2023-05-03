import os
import PyPDF2
import capstone.x86
import tempfile

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

""" Ins type """
INS_TYPE_JUMP = 0           # Direct and indirect jump
INS_TYPE_BRANCH = 1         # Conditional jump
INS_TYPE_CALL = 2
INS_TYPE_RETURN = 3
INS_TYPE_STANDARD = 4       # Any other instruction

""" Graphviz colors """
COLOR_BRANCH_TAKEN = 'chartreuse3'
COLOR_BRANCH_NOT_TAKEN = 'firebrick3'
COLOR_TAINTED = 'lightblue'

class CFGException(Exception):
    pass

class Ins:
    def __init__(self, dis, addr, opcodes, tainted=False, routine='', routine_addr=0x0, target_addr=0x0, comment=''):
        self.dis = dis
        self.addr = addr
        self.opcodes = opcodes
        self.size = len(opcodes)
        self.tainted = tainted
        self.routine = routine
        self.routine_addr = routine_addr
        self.target_addr = target_addr
        self.comment = comment
        self.type = self._get_ins_type()
        self.info = self._get_ins_info()

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

        if (self.type == INS_TYPE_STANDARD) or (self.type == INS_TYPE_BRANCH) or (self.type == INS_TYPE_CALL):
            ret['fallthrough'] = self.addr + self.size
        
        if (self.type == INS_TYPE_CALL) or (self.type == INS_TYPE_JUMP):
            operand = self.dis.operands[0] 
            ret['target'] = self.target_addr
            if operand.type == capstone.x86.X86_OP_IMM:
                ret['mode'] = 'direct'
            elif (operand.type == capstone.x86.X86_OP_MEM) or (operand.type == capstone.x86.X86_OP_REG):
                ret['mode'] = 'indirect'
            else:
                raise NotImplementedError(f'{self.dis.mnemonic} {self.dis.op_str}\t: Ins not supported')

        if self.type == INS_TYPE_RETURN:
            ret['target'] = self.target_addr

        if self.type == INS_TYPE_BRANCH:
            operand = self.dis.operands[0]
            if operand.type == capstone.x86.X86_OP_IMM:
                ret['branch-target'] = operand.imm

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
            operand = self.dis.operands[0]
            if operand.type == capstone.x86.X86_OP_MEM:
                return operand.value.mem.base == capstone.x86.X86_REG_RIP

        return False

    def is_standard(self):
        return self.type == INS_TYPE_STANDARD

    def is_control_flow(self):
        return not self.is_standard()

    def is_branch_taken(self, ins):
        if self.is_branch():
            return self.info['branch-target'] == ins.addr

        return False

    def get_ins_offset(self):
        return self.addr - self.routine_addr

    def check_next_ins(self, ins):
        if ins.addr != self.info['fallthrough']:
            raise CFGException(f'"{str(self)}" does not fallthrough to "{str(ins)}"')

    def update_comment(self, comment):
        if self.comment:
            self.comment += ', '
        
        self.comment += comment

    def dumps(self, opcodes_padding=0, comment_padding=0):
        tab_padding = ' ' * 5

        string = f'{hex(self.addr)}{tab_padding}{self.opcodes.hex().ljust(opcodes_padding)}{tab_padding}{self.dis.mnemonic} {self.dis.op_str}'

        if self.comment:
            string = f'{string.ljust(comment_padding)} ; {self.comment}'

        return string

    def __str__(self):
        return self.dumps()

    def __eq__(self, other):
        if isinstance(other, Ins):
            return (self.addr == other.addr) and (self.opcodes == other.opcodes)

        return False

class Group:
    def __init__(self, routine='', routine_addr=0x0):
        self.routine = routine
        self.routine_addr = routine_addr
        self.inss = []
        self.leader = None
        self.tail = None
        self.taint_count = 0

    def add(self, ins):
        if self.leader is None:
            self.leader = ins
        
        if self.tail is not None:
            self.tail.check_next_ins(ins)

        self.tail = ins

        self.inss.append(ins)

    def extend(self, group):
        for ins in group:
            if ins not in self.inss:
                self.add(ins)
        
        self.taint(group)

    def taint(self, group):
        """ Preserve taint count """
        self.taint_count += group.taint_count

    def __str__(self):
        return '\n'.join([str(ins) for ins in self.inss])

    def __len__(self):
        return len(self.inss)

    def __iter__(self):
        for ins in self.inss:
            yield ins

    def __eq__(self, other):
        if isinstance(other, Group):
            return self.leader == other.leader

        return False

class Edge:
    def __init__(self, dst):
        self.dst = dst
        self.count = 1
        self.branch_taken = False

    def __eq__(self, other):
        if isinstance(other, Edge):
            return self.dst == other.dst

        return False

class Node:
    def __init__(self, group):
        self.group = group
        self.visit_count = 1
        self.taint_count = group.taint_count
        self.edges = []
        self.diff = 0

    def taint(self, node):
        """ Preserve taint count """
        self.taint_count += node.taint_count

    def visit(self):
        self.visit_count += 1

    def is_tainted(self):
        return self.taint_count > 0

    def check_next_node(self, node):
        if self.group.tail.is_return():
            return

        if self.group.tail.is_jump():
            if self.group.tail.info['target'] == node.group.leader.addr:
                return

        if self.group.tail.is_branch():
            if (self.group.tail.info['branch-target'] == node.group.leader.addr) or (self.group.tail.info['fallthrough'] == node.group.leader.addr):
                return

        """ We can't know either fallthrough or target address during plt jmp """ 
        if self.group.tail.is_plt_jmp():
            return

        if self.group.tail.info['fallthrough'] == node.group.leader.addr:
            return
    
        raise CFGException(f'"{self.group.tail}" cannot be followed by "{node.group.leader}"')

    def extend(self, node):
        self.group.extend(node.group)

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.group == other.group

        return False

    def __len__(self):
        return len(self.group)

    def __str__(self):
        return str(self.group)

    def __iter__(self):
        for edge in self.edges:
            yield edge

    def __hash__(self):
        return self.group.leader.addr

class CFG:
    def __init__(self):
        self.nodes = []                 # List of nodes withouth any order
        self.entry_node = None          # Entry node of the CFG
        self.last_inserted = None       # Last node visited in the CFG
        self.next = []                  # CFGs reached from this CFG
        self.final_cfg = False          # CFG is the last executed
        self.final_nodes = []           # List of nodes that finalize CFG
        self.tainted = False            # CFG contains a tainted node?
        self.previous = None            # Previous CFG that calls this CFG
        self.refine = False             # Do we need to refine an already constructed CFG?
        self.branch_node = None         # Last node with a branch instruction

    def taint(self, node):
        """ Preserve if one of nodes was tainted at some time """
        self.tainted = self.tainted or node.is_tainted() 

    def is_empty(self):
        return self.entry_node is None

    def initialize(self):
        if not self.is_empty():
            self.last_inserted = self.entry_node
            self.refine = True

    def set_final(self):
        self.final_cfg = True

    def is_final(self):
        return self.final_cfg

    def finalize(self):
        if not self.is_empty():
            self.final_nodes.append(self.last_inserted)

    def _transition_to_first_edge(self, node):
        if self.last_inserted in self.final_nodes:
            self.last_inserted.visit()
            if len(node) > len(self.last_inserted):
                """
                If incoming node length is greater than last_inserted, it means the
                previous trace was stopped at this node. So, we need to extend the
                node to match its actual defined instructions
                """
                self.last_inserted.extend(node)
                """ We are updating the CFG, so do not store last_inserted as final node """
                while self.last_inserted in self.final_nodes:
                    self.final_nodes.remove(self.last_inserted)
                self.final_cfg = False
        else:
            if self.last_inserted.edges:
                """ Keep track of last branch node """
                self.branch_node = self.last_inserted if self.last_inserted.group.tail.is_branch() else None
                edge = self.last_inserted.edges[0]
                edge.count += 1
                """ Update node info """
                self.last_inserted.taint(node)
                self.last_inserted.visit()
                self.taint(node)
                self.last_inserted = edge.dst
            else:
                """
                CFG node ends here because it does not have a transition defined,
                so we deactivate refinement
                """
                self.refine = False
                self.final_cfg = False
                self.last_inserted.visit()

    def _transition_to_second_edge(self, node):
        """ Revert previous branch decision """
        self.branch_node.edges[0].count -= 1
        if len(self.branch_node.edges) == 2:
            """ Take second branch """
            edge = self.branch_node.edges[1]
            if edge.dst == node:
                edge.count += 1
                self.last_inserted = edge.dst
                """ Assume transition by the first edge again """
                self._transition_to_first_edge(node)
            else:
                raise CFGException(f'Unkown transition from "{self.branch_node.group.tail}" to "{node.group.leader}"')
        else:
            """ Add this transition to branch_node because is not yet defined """
            try:
                temp = self.last_inserted
                self.last_inserted = self.branch_node
                self._add_node(node)
            except CFGException:
                """
                Revert to real last_inserted because insertion in
                branch_node failed and raised exception
                """
                self.branch_node.edges[0].count += 1
                self.last_inserted = temp
                raise

    def _transition_to_node(self, node):
        """ Check if transition is already defined to the incoming node """
        for edge in self.last_inserted.edges:
            """ Check if transition is already defined and cosume its destination """
            if edge.dst == node:
                edge.count += 1
                self.last_inserted = edge.dst
                """ Update node info """
                self.last_inserted.taint(node)
                self.last_inserted.visit()
                self.taint(node)
                return True

        return False

    def _add_node_transition(self, node):
        new_edge = Edge(node)

        """ Check if new branch edge transition follows true or false predicate """
        if self.last_inserted.group.tail.is_branch():
            new_edge.branch_taken = self.last_inserted.group.tail.is_branch_taken(node.group.leader)

        self.last_inserted.edges.append(new_edge)
        self.last_inserted = node

        """ Keep track of all nodes """
        if node not in self.nodes:
            self.nodes.append(node)

    def _add_node(self, node):
        self.last_inserted.check_next_node(node)

        """ Search if node is already defined """
        if node in self.nodes:
            """
            Transition to the already defined node if current last_inserted does not
            containg a valid transition to node
            """
            if not self._transition_to_node(node):
                node_found = self.nodes[self.nodes.index(node)]
                """ Update info of previous defined node """
                node_found.visit()
                node_found.taint(node)
                self._add_node_transition(node_found)
        else:
            """ New transition to node """
            self._add_node_transition(node)

        """ We added a new node, so we do not need to keep track of last branch_node """
        self.branch_node = None

    def add(self, group):
        node = Node(group)

        if self.is_empty():
            self.entry_node = node
            self.last_inserted = self.entry_node
            self.nodes.append(node)
        else:
            if self.refine:
                if self.last_inserted == node:
                    """
                    Always assume transition by first edge, even if it is branch_node
                    with two transitions. At the moment we cannot tell which edge
                    should we take
                    """
                    self._transition_to_first_edge(node)
                elif self.branch_node is not None:
                    """
                    Assuming first transition of branch_node was wrong. So,
                    if branch_node is defined, revert transition and take the
                    second one
                    """
                    try:
                        self._transition_to_second_edge(node)
                    except CFGException:
                        """ Add new node, we are not refining the CFG anymore """
                        self.refine = False
                        self.final_cfg = False
                        self._add_node(node)
                else:
                    """ Otherwise assume the node was not yet visited in the CFG """
                    self._add_node(node)
            else:
                self._add_node(node)

    def __hash__(self):
        return self.entry_node.group.leader.addr

    def __eq__(self, other):
        if isinstance(other, CFG):
            return hash(self) == hash(other)

        return False

class DynamicCFG:
    def __init__(self):
        self.cfgs = []              # List of all CFGs without any order
        self.entry_cfg = None       # First CFG
        self.last_cfg = None        # Last CFG constructed

    def is_empty(self):
        return self.entry_cfg is None

    def initialize(self):
        if not self.is_empty():
            self.last_cfg = self.entry_cfg
            self.last_cfg.initialize()

    def finalize(self):
        if not self.is_empty():
            self.last_cfg.finalize()
            self.last_cfg.set_final()

    def add(self, group):
        if self.is_empty():
            cfg = CFG()
            cfg.add(group)
            self.entry_cfg = cfg
            self.last_cfg = self.entry_cfg
            self.cfgs.append(self.entry_cfg)
            if group.tail.is_return():
                group.tail.comment = 'return to undefined CFG'
        else:
            """ Go to another CFG due to call function """
            if group.tail.is_call():
                self.last_cfg.add(group)
                next_cfg = self.get_next(group)

                """ Next CFG is not defined yet, so we create a new one """
                if next_cfg is None:
                    cfg = CFG()
                    self.last_cfg.next.append(cfg)
                    temp = self.last_cfg
                    self.last_cfg = cfg
                    self.last_cfg.previous = temp
                    self.cfgs.append(self.last_cfg)
                else:
                    next_cfg.previous = self.last_cfg
                    self.last_cfg = next_cfg
                    self.last_cfg.initialize()
            elif group.tail.is_plt_jmp():
                """ plt jmp, fallthrough to the previous CFG """
                self.last_cfg.add(group)
                self.last_cfg.finalize()
                self.last_cfg = self.last_cfg.previous
            elif group.tail.is_return():
                """
                Fallthrough to the same CFG if there is no information about the
                previous CFG (we started tracing in the middle of a function)
                """
                if self.last_cfg.previous is None:
                    group.tail.comment = 'return to undefined CFG'

                self.last_cfg.add(group)

                """ Return to previous CFG """
                if self.last_cfg.previous is not None:
                    self.last_cfg.finalize()
                    self.last_cfg = self.last_cfg.previous
            else:
                self.last_cfg.add(group)

    def get_next(self, group):
        if not group.tail.is_call():
            raise CFGException(f'Could not retrieve next CFG, "{str(group.tail)}" is not a call ins')
        
        addr = group.tail.info['target']
        for cfg in self.cfgs:
            if not cfg.is_empty():
                if addr == hash(cfg):
                    return cfg

        return None

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
        opcodes_padding = max([len(ins.opcodes.hex()) for ins in cfg.entry_node.group.inss])
        comment_padding = max([len(ins.dumps(opcodes_padding=opcodes_padding).split(';')[0]) for ins in cfg.entry_node.group.inss])
        label = f'; {cfg.entry_node.group.leader.routine}'
        offset = cfg.entry_node.group.leader.get_ins_offset()
        if offset > 0:
            label += f' + {offset:#x}'
        if cfg.entry_node.taint_count > 0:
            label += f' [taint {cfg.entry_node.taint_count}/{cfg.entry_node.visit_count}]'
        label += '\l\l' + '\l'.join([ins.dumps(opcodes_padding=opcodes_padding, comment_padding=comment_padding) for ins in cfg.entry_node.group.inss]) + '\l'     # '\l' means left-aligned, last one is mandatory to ensure alignment of label last line

        if cfg.entry_node.is_tainted():
            graph.node(entry_node_id, label=label, style='filled', fillcolor=COLOR_TAINTED)
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
                    """ Calculate padding """
                    opcodes_padding = max([len(ins.opcodes.hex()) for ins in edge.dst.group.inss])
                    comment_padding = max([len(ins.dumps(opcodes_padding=opcodes_padding).split(';')[0]) for ins in edge.dst.group.inss])
                    """ Label with routine offset """
                    label = f'; {edge.dst.group.leader.routine}'
                    offset = edge.dst.group.leader.get_ins_offset()
                    if offset > 0:
                        label += f' + {offset:#x}'
                    if edge.dst.taint_count > 0:
                        label += f' [taint {edge.dst.taint_count}/{edge.dst.visit_count}]'
                    label += '\l\l'
                    label += '\l'.join([ins.dumps(opcodes_padding=opcodes_padding, comment_padding=comment_padding) for ins in edge.dst.group.inss])
                    label += '\l'                                      # '\l' means left-aligned, last one is mandatory to ensure alignment of label last line
                    """ Light blue for taint information """
                    if edge.dst.is_tainted():
                        graph.node(edge_node_id, label=label, style='filled', fillcolor=COLOR_TAINTED)
                    else:
                        graph.node(edge_node_id, label=label)
                    """ True or false branch jump """
                    if node.group.tail.is_branch():
                        if edge.branch_taken:
                            graph.edge(node_id, edge_node_id, label=f't / {edge.count}', color=COLOR_BRANCH_TAKEN)
                        else:
                            graph.edge(node_id, edge_node_id, label=f'f / {edge.count}', color=COLOR_BRANCH_NOT_TAKEN)
                    else:
                        graph.edge(node_id, edge_node_id, label=str(edge.count))
                    already_seen.append((node_id, edge_node_id))

                    new_edges = (edge.dst, edge.dst.edges)
                    pending_edges.append(new_edges)

        """ CFG last transition """
        if cfg.is_final() and len(cfg.final_nodes):
            graph.node('final', label='', shape='doublecircle', style='filled', color='black', fixedsize='true')

            already_seen = []
            for last_node in cfg.final_nodes:
                last_node_id = hex(last_node.group.leader.addr)
                if last_node_id not in already_seen:
                    graph.edge(last_node_id, 'final', label=f'{len(cfg.final_nodes)}')
                    graph.node(last_node_id)
                    already_seen.append(last_node_id)

        """ Generate Graphviz DOT file (.gv) """
        graph.render()

    def export_graph(self, output):
        if not self.is_empty():
            filenames = []

            """ Automatically deletes temp_dir and all its content """
            with tempfile.TemporaryDirectory() as temp_dir:
                pending_cfgs = []
                cfg = self.entry_cfg
                cfg_output_filename = os.path.join(temp_dir, hex(hash(cfg)))
                self._export_cfg(cfg, cfg_output_filename, first=True)
                filenames.append(cfg_output_filename)
                pending_cfgs.extend(cfg.next)

                while pending_cfgs:
                    cfg = pending_cfgs.pop(0)
                    cfg_output_filename = os.path.join(temp_dir, hex(hash(cfg)))
                    if cfg_output_filename not in filenames:
                        self._export_cfg(cfg, cfg_output_filename)
                        filenames.append(cfg_output_filename)
                    pending_cfgs.extend(cfg.next)

                """ Join temp files """
                merger = PyPDF2.PdfMerger()
                for filename in filenames:
                    merger.append(f'{filename}.gv.pdf')

                merger.write(output)
                merger.close()
