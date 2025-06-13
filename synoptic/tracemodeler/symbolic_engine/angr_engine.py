""" Disable {DEBUG, WARNING, INFO} logging for angr libraries """
import logging
for module in ['angr', 'ailment', 'claripy', 'cle', 'pyvex']:
    logging.getLogger(module).setLevel(logging.ERROR)
import angr
import claripy
import capstone.x86

import synoptic.debug as debug
import synoptic.utils as utils

class AngrEngine():
    def __init__(self, binary, binary_args, timeout):
        self.name = 'angr'
        self.binary = binary
        self.binary_args = binary_args
        self.timeout = timeout
        self.project = None
        self.state = None
        self.buffer = None
        self.goal_addr = None
        self.cut_addr = []

    def get_name(self):
        return self.name

    def get_timeout(self):
        return self.timeout

    def open_binary(self, base_addr):
        self.project = angr.Project(self.binary, main_opts={'base_addr': base_addr}, auto_load_libs=True)    # Resolve lazy bindings

    def start(self, start_addr):
        self.state = self.project.factory.blank_state(addr=start_addr)

    def symbolic_buffer(self, reg_id, reg_name, length):
        buff_addr = 0xfffff000000000
        buff = claripy.BVS(reg_name, length * 8)
        self.buffer = buff
        self.state.memory.store(buff_addr, buff)

        self._set_state_reg(reg_id, buff_addr)

    def symbolic_reg(self, reg_id, reg_name, reg_size):
        reg = claripy.BVS(reg_name, reg_size * 8)
        self._set_state_reg(reg_id, reg)

    def goal(self, goal_addr):
        self.goal_addr = goal_addr

    def cut(self, cut_addr):
        self.cut_addr.append(cut_addr)

    def run(self, n_solutions):
        if self.buffer is None:
            debug.warning(f'Symbolic analysis\t: Symbolic buffer not defined, skipping...')
            return []
        
        if self.goal_addr is None:
            debug.warning(f'Symbolic analysis\t: Goal not defined, skipping...')
            return []

        if not self.cut_addr:
            debug.warning(f'Symbolic analysis\t: Cut not defined, skipping...')
            return []

        sm = self.project.factory.simulation_manager(self.state)
        """ Timeout is reset after each result found """
        utils.setup_timeout(self.timeout)
        sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()                      # Unstash solution once found
        utils.disable_timeout()

        for found in sm.found:
            solutions = found.solver.eval_upto(self.buffer, n_solutions, cast_to=bytes)     # Up to n_solutions solution 
            yield solutions
            utils.setup_timeout(self.timeout)
            sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()
            utils.disable_timeout()

    def clean_project(self):
        self.state = None
        self.buffer = None
        self.goal_addr = None
        self.cut_addr = []

    def _set_state_reg(self, reg_id, value):
        if reg_id == capstone.x86.X86_REG_AH:
            self.state.regs.ah = value
        elif reg_id == capstone.x86.X86_REG_AL:
            self.state.regs.al = value
        elif reg_id == capstone.x86.X86_REG_AX:
            self.state.regs.ax = value
        elif reg_id == capstone.x86.X86_REG_BH:
            self.state.regs.bh = value
        elif reg_id == capstone.x86.X86_REG_BL:
            self.state.regs.bl = value
        elif reg_id == capstone.x86.X86_REG_BP:
            self.state.regs.bp = value
        elif reg_id == capstone.x86.X86_REG_BPL:
            self.state.regs.bpl = value
        elif reg_id == capstone.x86.X86_REG_BX:
            self.state.regs.bx = value
        elif reg_id == capstone.x86.X86_REG_CH:
            self.state.regs.ch = value
        elif reg_id == capstone.x86.X86_REG_CL:
            self.state.regs.cl = value
        elif reg_id == capstone.x86.X86_REG_CX:
            self.state.regs.cx = value
        elif reg_id == capstone.x86.X86_REG_DH:
            self.state.regs.dh = value
        elif reg_id == capstone.x86.X86_REG_DI:
            self.state.regs.di = value
        elif reg_id == capstone.x86.X86_REG_DIL:
            self.state.regs.dil = value
        elif reg_id == capstone.x86.X86_REG_DL:
            self.state.regs.dl = value
        elif reg_id == capstone.x86.X86_REG_DX:
            self.state.regs.dx = value
        elif reg_id == capstone.x86.X86_REG_EAX:
            self.state.regs.eax = value
        elif reg_id == capstone.x86.X86_REG_EBX:
            self.state.regs.ebx = value
        elif reg_id == capstone.x86.X86_REG_ECX:
            self.state.regs.ecx = value
        elif reg_id == capstone.x86.X86_REG_EDI:
            self.state.regs.edi = value
        elif reg_id == capstone.x86.X86_REG_EDX:
            self.state.regs.edx = value
        elif reg_id == capstone.x86.X86_REG_ESI:
            self.state.regs.esi = value
        elif reg_id == capstone.x86.X86_REG_RAX:
            self.state.regs.rax = value
        elif reg_id == capstone.x86.X86_REG_RBX:
            self.state.regs.rbx = value
        elif reg_id == capstone.x86.X86_REG_RCX:
            self.state.regs.rcx = value
        elif reg_id == capstone.x86.X86_REG_RDI:
            self.state.regs.rdi = value
        elif reg_id == capstone.x86.X86_REG_RDX:
            self.state.regs.rdx = value
        elif reg_id == capstone.x86.X86_REG_RSI:
            self.state.regs.rsi = value
        elif reg_id == capstone.x86.X86_REG_SI:
            self.state.regs.si = value
        elif reg_id == capstone.x86.X86_REG_SIL:
            self.state.regs.sil = value
        elif reg_id == capstone.x86.X86_REG_R8:
            self.state.regs.r8 = value
        elif reg_id == capstone.x86.X86_REG_R9:
            self.state.regs.r9 = value
        elif reg_id == capstone.x86.X86_REG_R10:
            self.state.regs.r10 = value
        elif reg_id == capstone.x86.X86_REG_R11:
            self.state.regs.r11 = value
        elif reg_id == capstone.x86.X86_REG_R12:
            self.state.regs.r12 = value
        elif reg_id == capstone.x86.X86_REG_R13:
            self.state.regs.r13 = value
        elif reg_id == capstone.x86.X86_REG_R14:
            self.state.regs.r14 = value
        elif reg_id == capstone.x86.X86_REG_R15:
            self.state.regs.r15 = value
        elif reg_id == capstone.x86.X86_REG_R8B:
            self.state.regs.r8b = value
        elif reg_id == capstone.x86.X86_REG_R9B:
            self.state.regs.r9b = value
        elif reg_id == capstone.x86.X86_REG_R10B:
            self.state.regs.r10b = value
        elif reg_id == capstone.x86.X86_REG_R11B:
            self.state.regs.r11b = value
        elif reg_id == capstone.x86.X86_REG_R12B:
            self.state.regs.r12b = value
        elif reg_id == capstone.x86.X86_REG_R13B:
            self.state.regs.r13b = value
        elif reg_id == capstone.x86.X86_REG_R14B:
            self.state.regs.r14b = value
        elif reg_id == capstone.x86.X86_REG_R15B:
            self.state.regs.r15b = value
        elif reg_id == capstone.x86.X86_REG_R8D:
            self.state.regs.r8d = value
        elif reg_id == capstone.x86.X86_REG_R9D:
            self.state.regs.r9d = value
        elif reg_id == capstone.x86.X86_REG_R10D:
            self.state.regs.r10d = value
        elif reg_id == capstone.x86.X86_REG_R11D:
            self.state.regs.r11d = value
        elif reg_id == capstone.x86.X86_REG_R12D:
            self.state.regs.r12d = value
        elif reg_id == capstone.x86.X86_REG_R13D:
            self.state.regs.r13d = value
        elif reg_id == capstone.x86.X86_REG_R14D:
            self.state.regs.r14d = value
        elif reg_id == capstone.x86.X86_REG_R15D:
            self.state.regs.r15d = value
        elif reg_id == capstone.x86.X86_REG_R8W:
            self.state.regs.r8w = value
        elif reg_id == capstone.x86.X86_REG_R9W:
            self.state.regs.r9w = value
        elif reg_id == capstone.x86.X86_REG_R10W:
            self.state.regs.r10w = value
        elif reg_id == capstone.x86.X86_REG_R11W:
            self.state.regs.r11w = value
        elif reg_id == capstone.x86.X86_REG_R12W:
            self.state.regs.r12w = value
        elif reg_id == capstone.x86.X86_REG_R13W:
            self.state.regs.r13w = value
        elif reg_id == capstone.x86.X86_REG_R14W:
            self.state.regs.r14w = value
        elif reg_id == capstone.x86.X86_REG_R15W:
            self.state.regs.r15w = value
        else:
            raise NotImplementedError(f'angr reg (ID: {reg_id}) not supported')
