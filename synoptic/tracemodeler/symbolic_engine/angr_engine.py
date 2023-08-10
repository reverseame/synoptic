""" Disable {DEBUG, WARNING, INFO} logging for angr libraries """
import logging
for module in ['angr', 'ailment', 'claripy', 'cle', 'pyvex']:
    logging.getLogger(module).setLevel(logging.ERROR)
import angr
import claripy

import synoptic.debug as debug
import synoptic.utils as utils

class AngrEngine():
    def __init__(self, binary, timeout):
        self.name = 'angr'
        self.binary = binary
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

    def run(self, n_solutions):
        if self.buffer is None:
            debug.warning(f'Symbolic analysis\t: Symbolic buffer not defined, skipping...')
            return
        
        if self.goal_addr is None:
            debug.warning(f'Symbolic analysis\t: Goal not defined, skipping...')
            return

        if not self.cut_addr:
            debug.warning(f'Symbolic analysis\t: Cut not defined, skipping...')
            return

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