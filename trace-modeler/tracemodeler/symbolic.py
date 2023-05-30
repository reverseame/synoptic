import tracemodeler.symbolic_engine.angr_engine
import tracemodeler.symbolic_engine.binsec_engine

class SymbolicEngine():
    def __init__(self, symbolic, binary):
        if symbolic == 'angr':
            self.engine = tracemodeler.symbolic_engine.angr_engine.AngrEngine(binary)
        elif symbolic == 'binsec':
            self.engine = tracemodeler.symbolic_engine.binsec_engine.BinsecEngine(binary)
        else:
            raise ValueError(f'{symbolic}\t: Unknown symbolic engine')

    def open_binary(self, base_addr):
        self.engine.open_binary(base_addr)

    def symbolic_buffer(self, reg_id, reg_name, length=100):
        self.engine.symbolic_buffer(reg_id, reg_name, length)

    def symbolic_reg(self, reg_id, reg_name):
        self.engine.symbolic_reg(reg_id, reg_name, length)

    def start(self, start_addr):
        self.engine.start(start_addr)

    def goal(self, goal_addr):
        self.engine.goal(goal_addr)

    def cut(self, cut_addr):
        self.engine.cut(cut_addr)

    def run(self, timeout=5, n_solutions=10):
        yield from self.engine.run(timeout, n_solutions)
