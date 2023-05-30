""" Disable INFO logging for angr libraries """
import logging
for module in ['angr', 'ailment', 'claripy', 'cle', 'pyvex']:
    logging.getLogger(module).setLevel(logging.WARNING)
import angr
import claripy

class AngrEngine():
    def __init__(self, binary):
        self.binary = binary
        self.project = None
        self.state = None
        self.buffer = None
        self.goal_addr = None
        self.cut_addr = []

    def open_binary(self, base_addr):
        self.project = angr.Project(self.binary, main_opts={'base_addr': base_addr}, auto_load_libs=True)    # Lazy bindings

    def start(self, start_addr):
        self.state = self.project.factory.entry_state(addr=start_addr)

    def symbolic_buffer(self, reg_id, reg_name, length):
        buff = claripy.BVS('buffer', length * 8)
        buff_addr = 0xfffff000000000
        self.state.memory.store(buff_addr, buff)

        reg = self.state.regs.get(reg_name)
        reg = buff_addr

        self.buffer = buff

    def symbolic_reg(self, reg_id, reg_name):
        pass
    
    def goal(self, goal_addr):
        self.goal_addr = goal_addr

    def cut(self, cut_addr):
        self.cut_addr.append(cut_addr)

    def run(self, n_solutions):
        ret = []

        sm = self.project.factory.simulation_manager(self.state)
        sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()                      # Unstash solution once found

        for found in sm.found:
            solutions = found.solver.eval_upto(self.buffer, n_solutions, cast_to=bytes)     # Up to 10 solution 
            ret.append(solutions)
            sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()

        return ret
