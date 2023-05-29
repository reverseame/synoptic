""" Disable INFO logging for angr libraries """
import logging
for module in ['angr', 'ailment', 'claripy', 'cle', 'pyvex']:
    logging.getLogger(module).setLevel(logging.WARNING)
import angr

class AngrEngine():
    def __init__(self):
        self.project = None

    def binary(self, binary, base_addr):
        self.project = angr.Project(binary, main_opts={'base_addr': base_addr}, auto_load_libs=True)    # Lazy bindings
