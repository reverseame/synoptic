import enum
import capstone.x86

INS_TYPE_JUMP = 0        # Direct and indirect jump
INS_TYPE_BRANCH = 1      # Conditional jump
INS_TYPE_CALL = 2
INS_TYPE_RETURN = 3
INS_TYPE_STANDARD = 4    # Any other instruction

class Ins:
    def __init__(self, addr, opcodes, dis):
        self.addr = addr
        self.opcodes = opcodes
        self.size = len(opcodes)
        self.dis = dis
        self.type = self._get_ins_type(dis)
        self.info = self._get_ins_info(dis)

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
        elif dis.operands[0].type == capstone.x86.X86_OP_REG:
            import pdb; pdb.set_trace()

        if (self.type == INS_TYPE_BRANCH) or (self.type == INS_TYPE_CALL):
            ret['fallthrough'] = self.addr + self.size

        return ret

    def __eq__(self, other):
        if isinstance(other, Ins):
            return (self.addr == other.addr) and (self.opcodes == other.opcodes)

        return False

    def __str__(self):
        return f'{hex(self.addr)}: {self.dis.mnemonic} {self.dis.op_str}'

class Group:
    def __init__(self):
        self.inss = []
        self.leader = None
        self.tail = None

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
        self.edges = []

    def transition(self, dst):
        new_edge = Edge(dst)

        if new_edge in self.edges:
            import pdb; pdb.set_trace()
            edge = self.edges[self.edges.index(new_edge)]
            edge.count += 1
            return edge.dst
        else:
            self.edges.append(new_edge)
            return new_edge.dst

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.group == other.group

        return False

    def __str__(self):
        return str(self.group)

    def __iter__(self):
        for edge in self.edges:
            yield edge

class CFG:
    def __init__(self):
        self.entry = None
        self.index = None

    def is_empty(self):
        return self.entry is None

    def initialize(self):
        self.index = self.entry

    def add(self, group):
        node = Node(group)

        if self.is_empty():
            self.entry = node
            self.index = node
        else:
            self.index = self.index.transition(node)

    def __iter__(self):
        raise NotImplementedError
