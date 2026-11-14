import os
import re
import r2pipe
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
        config_file = self._generate_config_file(core_file)

        command = [self.binsec_path, '-sse', '-sse-script', config_file, '-smt-timeout', str(self.timeout), core_file]

        """ [sse:result] Value @[buffer<64>,<-,${length}] : 0x${little-endian hex value} """
        result = re.compile(r'^\[sse:result\] Value @\[buffer<64>,<-,(\d+)\] : 0x([0-9a-fA-F]+)$')

        p = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, errors='replace')
        try:
            """ As with angr, the exploration timeout is reset after each result found """
            utils.setup_timeout(self.timeout)
            for line in p.stdout:
                match = result.match(line.strip())
                if match:
                    utils.disable_timeout()
                    length = int(match.group(1))
                    yield [int(match.group(2), 16).to_bytes(length, 'little')]
                    utils.setup_timeout(self.timeout)
        finally:
            utils.disable_timeout()
            p.kill()
            p.wait()

    def clean_project(self):
        self.start_addr = None
        self.buffer = None
        self.regs = []
        self.goal_addr = None
        self.cut_addr = []

    def _translate_addr(self, addr):
        return (addr - self.base_addr) + DEFAULT_LINUX_ADDR

    def _generate_core_dump(self):
        command = [shutil.which('gdb')]
        (gdb_script, core_file) = self._generate_gdb_script()
        command.extend(['-x', gdb_script])
        command.extend(['--args', self.binary, self.binary_args])

        subprocess.check_output(command, stderr=subprocess.STDOUT)
        
        return core_file

    def _generate_gdb_script(self):
        template_file = os.path.join(utils.TOOL_ROOT_DIR, 'synoptic', 'tracemodeler', 'symbolic_engine', 'binsec_templates', 'generate-core-file.gdb')

        with open(template_file, 'r') as f:
            template_data = f.readlines()

        gdb_script = os.path.join(self.temp_dir, 'generate-core-file.gdb')

        with open(gdb_script, 'w') as f:
            for line in template_data:
                if 'generate-core-file' in line:
                    template_string = string.Template(line)
                    core_file = os.path.join(self.temp_dir, 'core.snapshot')
                    line = template_string.substitute(core_file=core_file)

                f.write(line)

        return (gdb_script, core_file)

    def _generate_config_file(self, core_file):
        r2 = r2pipe.open(core_file, flags=['-2'])
        core_program_counter = r2.cmd('dr rip').rstrip()
        r2.quit()

        template_file = os.path.join(utils.TOOL_ROOT_DIR, 'synoptic', 'tracemodeler', 'symbolic_engine', 'binsec_templates', 'config.ini')

        with open(template_file, 'r') as f:
            template = string.Template(f.read())

        (_, _, length) = self.buffer
        script = template.substitute(core_program_counter=core_program_counter,
                                     start_addr=hex(self.start_addr),
                                     goal_addr=hex(self.goal_addr),
                                     symbolic_data=self._set_up_regs() + self._set_up_buffer(),
                                     buffer_length=length,
                                     cut_data=''.join(f'cut at {hex(addr)}\n' for addr in self.cut_addr))

        config_file = os.path.join(self.temp_dir, 'config.ini')

        with open(config_file, 'w') as f:
            f.write(script)

        return config_file

    def _set_up_regs(self):
        string = '# symbolic regs\n'

        for (_, reg_name, _) in self.regs:
            string += f'\t{reg_name} := nondet\n'

        return string

    def _set_up_buffer(self):
        string = '\n\t# symbolic buffer, its address kept in a variable to print it at the goal\n'

        (_, reg_name, length) = self.buffer

        string += f'\tbuffer<64> := {reg_name}\n'
        string += f'\tfor i<64> in 0 to {length-1} do\n'
        string += f'\t\t@[buffer + i] := nondet\n'
        string += f'\tend\n'

        return string

    def __del__(self):
        """ Clean up temp folder """
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except OSError:
                debug.warning(f'{self.temp_dir}\t: Unable to delete temporary folder')
