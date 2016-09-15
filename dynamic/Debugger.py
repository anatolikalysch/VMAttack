# coding=utf-8
__author__ = 'Anatoli Kalysch'


class Debugger(object):
    def __init__(self):
        self.registers = []
        self.hooked = False
        self.stack = []
        self.binary = None
        self._module_name = "NoDBG"
        self.error_msg = "Please specify a Debugger!"

    @property
    def module_name(self):
        return self._module_name

    def set_breakpoint(self, address):
        return self.error_msg

    def remove_breakpoint(self, address):
        return self.error_msg

    def single_step(self):
        return self.error_msg

    def hook_dbg(self):
        return self.error_msg

    def unhook_dbg(self):
        return self.error_msg

    def gen_trace(self, trace_start, trace_end):
        return self.error_msg

    def get_env_context(self):
        return self.error_msg

    def set_env_context(self, ctx):
        return self.error_msg
