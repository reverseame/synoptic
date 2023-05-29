import tracemodeler.symbolic_engine.angr_engine
import tracemodeler.symbolic_engine.binsec_engine

class SymbolicEngine():
    def __init__(self, symbolic):
        if symbolic == 'angr':
            self.engine = tracemodeler.symbolic_engine.angr_engine.AngrEngine()
        elif symbolic == 'binsec':
            self.engine = tracemodeler.symbolic_engine.binsec_engine.BinsecEngine()
        else:
            raise ValueError(f'{symbolic}\t: Unknown symbolic engine')

    def binary(self, binary, base_addr):
        self.engine.binary(binary, base_addr)
