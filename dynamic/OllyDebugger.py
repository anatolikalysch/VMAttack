# coding=utf-8
__author__ = 'Anatoli Kalysch'

from Debugger import Debugger
import sys
from ollyapi import *

# TODO this is a stub and will be completed later
class OllyDebugger(Debugger):
    def __init__(self, *args):
        super(Debugger, self).__init__()
        self.steps = 0
        self.hooked = False
        self.bp = None
        self.callstack = {}
        self.prev_bp_ea = None
        self._module_name = 'OllyDbg'
        self.start_time = 0
        self.end_time = 0

        self.error_msg = "TODO!"

    def set_breakpoint(self, address):
        return self.error_msg

    def remove_breakpoint(self, address):
        return self.error_msg

    def single_step(self):
        return self.error_msg

    def gen_trace(self):
        return self.error_msg

    def part_exec(self, start=None, end=None, reg_ctx=None):
        return self.error_msg

    def get_env_context(self):
        return self.error_msg