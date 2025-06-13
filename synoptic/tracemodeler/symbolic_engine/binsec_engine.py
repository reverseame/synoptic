import os
import r2pipe
import shutil
import string
import struct
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
        self.cut_addr = None
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
        self.cut_addr = self._translate_addr(cut_addr)

    def run(self, n_solutions):
        if self.buffer is None:
            debug.warning(f'Symbolic analysis\t: Symbolic buffer not defined, skipping...')
            return []
        
        if self.goal_addr is None:
            debug.warning(f'Symbolic analysis\t: Goal not defined, skipping...')
            return []

        if self.cut_addr is None:
            debug.warning(f'Symbolic analysis\t: Cut not defined, skipping...')
            return []

        core_file = self._generate_core_dump()
        config_file = self._generate_config_file(core_file)

        command = [self.binsec_path, '-sse', '-sse-script',
                    config_file, core_file, '-fml-solver-timeout', str(self.timeout)]

        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as p:
            for line in p.stdout:
                if '[sse:result] Ascii stream' in line:
                    """ [sse:result] Ascii stream ${variable} : "${solution}"\n """
                    solution = line.split(' : ')[-1][1:-2]
                    yield [self._encode_buffer(solution)]

    def clean_project(self):
        self.start_addr = None
        self.buffer = None
        self.regs = []
        self.goal_addr = None
        self.cut_addr = None

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
            template_data = f.readlines()

        config_file = os.path.join(self.temp_dir, 'config.ini')

        with open(config_file, 'w') as f:
            for line in template_data:
                if 'core_program_counter<64>' in line:
                    template_string = string.Template(line)
                    line = template_string.substitute(core_program_counter=core_program_counter)
                elif 'start_addr<64>' in line:
                    template_string = string.Template(line)
                    line = template_string.substitute(start_addr=hex(self.start_addr))
                elif 'goal_addr<64>' in line:
                    template_string = string.Template(line)
                    line = template_string.substitute(goal_addr=hex(self.goal_addr))
                elif 'cut_addr<64>' in line:
                    template_string = string.Template(line)
                    line = template_string.substitute(cut_addr=hex(self.cut_addr))
                elif 'symbolic_data' in line:
                    template_string = string.Template(line)
                    symbolic_data = self._set_up_regs()
                    symbolic_data += self._set_up_buffer()
                    line = template_string.substitute(symbolic_data=symbolic_data)

                f.write(line)

        return config_file

    def _set_up_regs(self):
        string = '# symbolic regs\n'

        for (_, reg_name, _) in self.regs:
            string += f'\t{reg_name} := nondet\n'

        return string

    def _set_up_buffer(self):
        string = '\n\t# symbolic buffer\n'

        (_, reg_name, length) = self.buffer

        string += f'\t@[{reg_name}, {length}] := 0\n'
        string += f'\tfor i<64> in 0 to {length-1} do\n'
        string += f'\t\t@[{reg_name} + i] := nondet as token\t# fill buffer with symbolic values\n'
        string += f'\tend\n'

        return string

    def _encode_buffer(self, buffer):
        for byte in range(0x00, 0xff):
            buffer = buffer.replace(rf'\0{byte:02x}', chr(byte))

        return buffer.encode()

    def __del__(self):
        """ Clean up temp folder """
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except OSError:
                debug.warning(f'{self.temp_dir}\t: Unable to delete temporary folder')
