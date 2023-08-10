import shutil

class BinsecEngine:
    def __init__(self, binary, timeout):
        self.name = 'binsec'
        self.binsec_path = shutil.which('binsec')
        self.binary = binary
        self.timeout = timeout
        self.base_addr = None
        self.start_addr = None
        self.buffer = None
        self.regs = []
        self.goal_addr = None
        self.cut_addr = []

    def get_name(self):
        return self.name

    def get_timeout(self):
        return self.timeout

    def open_binary(self, base_addr):
        self.base_addr = base_addr

    def start(self, start_addr):
        self.start_addr = start_addr

    def symbolic_buffer(self, reg_id, reg_name, length):
        self.buffer = (reg_name, length)

    def symbolic_reg(self, reg_id, reg_name):
        self.regs.append(reg_name)

    def goal(self, goal_addr):
        self.goal_addr = goal_addr

    def cut(self, cut_addr):
        self.cut_addr.append(cut_addr)

    def run(self, timeout, n_solutions):
        raise NotImplementedError(f'Binsec symbolic simulation not implemented')
