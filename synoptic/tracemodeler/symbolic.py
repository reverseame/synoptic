import synoptic.tracemodeler.symbolic_engine.angr_engine
import synoptic.tracemodeler.symbolic_engine.binsec_engine

class SymbolicEngine():
    def __init__(self, symbolic, binary, binary_args, timeout):
        if symbolic == 'angr':
            self.engine = synoptic.tracemodeler.symbolic_engine.angr_engine.AngrEngine(binary, binary_args, timeout)
        elif symbolic == 'binsec':
            self.engine = synoptic.tracemodeler.symbolic_engine.binsec_engine.BinsecEngine(binary, binary_args, timeout)
        else:
            raise ValueError(f'{symbolic}\t: Unknown symbolic engine')

    def get_name(self):
        return self.engine.get_name()

    def get_timeout(self):
        return self.engine.get_timeout()

    def open_binary(self, base_addr):
        self.engine.open_binary(base_addr)

    def symbolic_buffer(self, reg_id, reg_name, length=100):
        self.engine.symbolic_buffer(reg_id, reg_name, length)

    def symbolic_reg(self, reg_id, reg_name, reg_size):
        """ reg_size in bytes, for example: rax reg should be 8 bytes """
        self.engine.symbolic_reg(reg_id, reg_name, reg_size)

    def start(self, start_addr):
        self.engine.start(start_addr)

    def goal(self, goal_addr):
        self.engine.goal(goal_addr)

    def cut(self, cut_addr):
        self.engine.cut(cut_addr)

    def run(self, n_solutions=1):
        yield from self.engine.run(n_solutions)

    def clean_project(self):
        self.engine.clean_project()
