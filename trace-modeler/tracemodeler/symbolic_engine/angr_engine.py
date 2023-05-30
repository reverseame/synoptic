""" Disable {DEBUG, WARNING, INFO} logging for angr libraries """
import logging
for module in ['angr', 'ailment', 'claripy', 'cle', 'pyvex']:
    logging.getLogger(module).setLevel(logging.ERROR)
import angr
import claripy

import tracemodeler.debug as debug
import tracemodeler.utils as utils

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
        self.state = self.project.factory.blank_state(addr=start_addr)

    def symbolic_buffer(self, reg_id, reg_name, length):
        buff_addr = 0xfffff000000000
        buff = claripy.BVS('buffer', length * 8)
        self.buffer = buff
        self.state.memory.store(buff_addr, buff)

        utils.set_angr_reg(self.state, reg_id, buff_addr)

    def symbolic_reg(self, reg_id, reg_name):
        pass
    
    def goal(self, goal_addr):
        self.goal_addr = goal_addr

    def cut(self, cut_addr):
        self.cut_addr.append(cut_addr)

    def run(self, timeout, n_solutions):
        if self.buffer is None:
            debug.warning(f'Symbolic buffer not defined, skipping...')
            return
        
        if self.goal_addr is None:
            debug.warning(f'Goal not defined, skipping...')
            return

        if not self.cut_addr:
            debug.warning(f'Cut not defined, skipping...')
            return

        self.state.solver._solver.timeout = timeout * 1000          # Convert to miliseconds
        sm = self.project.factory.simulation_manager(self.state)
        sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()                      # Unstash solution once found

        for found in sm.found:
            solutions = found.solver.eval_upto(self.buffer, n_solutions, cast_to=bytes)     # Up to 10 solution 
            yield solutions
            sm.explore(find=self.goal_addr, avoid=self.cut_addr).unstash()
