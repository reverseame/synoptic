import os
import shutil
import string
import tempfile
import subprocess

import synoptic.debug as debug
import synoptic.utils as utils

""" Default Linux base address when ASLR is disabled """
DEFAULT_LINUX_ADDR = 0x555555554000

class BinsecEngine:
    def __init__(self, binary, binary_args, timeout):
        self.name = 'binsec'
        self.binsec_path = shutil.which('binsec')
        self.binary = binary
        self.binary_args = binary_args
        self.timeout = timeout
        self.base_addr = None
        self.start_addr = None
        self.buffer = None
        self.regs = []
        self.goal_addr = None
        self.cut_addr = []
        self.temp_dir = tempfile.mkdtemp()

    def get_name(self):
        return self.name

    def get_timeout(self):
        return self.timeout

    def open_binary(self, base_addr):
        self.base_addr = base_addr

    def start(self, start_addr):
        self.start_addr = self._translate_addr(start_addr)

    def symbolic_buffer(self, reg_id, reg_name, length):
        self.buffer = (reg_id, reg_name, length)

    def symbolic_reg(self, reg_id, reg_name, reg_size):
        self.regs.append((reg_id, reg_name, reg_size))

    def goal(self, goal_addr):
        self.goal_addr = self._translate_addr(goal_addr)

    def cut(self, cut_addr):
        self.cut_addr.append(self._translate_addr(cut_addr))

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

        core_file = self._generate_core_dump()

        import pdb; pdb.set_trace()

    def clean_project(self):
        self.start_addr = None
        self.buffer = None
        self.regs = []
        self.goal_addr = None
        self.cut_addr = []

    def _translate_addr(self, addr):
        return (addr - self.base_addr) + DEFAULT_LINUX_ADDR

    def _generate_core_dump(self):
        command = shutil.which('gdb')
        (gdb_script, core_file) = self._generate_gdb_script()
        command += f' -x {gdb_script}'
        command += f' --args {self.binary} {self.binary_args}'

        subprocess.run(command, cwd=self.temp_dir)
        
        return core_file

    def _generate_gdb_script(self):
        template_file = os.path.join(utils.TOOL_ROOT_DIR, 'tracemodeler', 'symbolic_engine', 'binsec_templates', 'generate-core-file.gdb')

        with open(template_file, 'r') as f:
            template_data = f.read().splitlines()

        gdb_script = os.path.join(self.temp_dir, 'generate-core-file.gdb')

        with open(gdb_script, 'w') as f:
            for line in template_data:
                if 'generate-core-file' in line:
                    template_string = string.Template(line)
                    core_file = os.path.join(self.temp_dir, 'core.snapshot')
                    line = template_string.substitute(core_file=core_file)

                f.write(f'{line}\n')

        return (gdb_script, core_file)

    def _generate_ini_file(self):
        pass

    def __del__(self):
        """ Clean up temp folder """
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except OSError:
                debug.warning(f'{self.temp_dir}\t: Unable to delete temporary folder')
