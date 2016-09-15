# coding=utf-8
__author__ = 'Anatoli Kalysch'

from idaapi import BADADDR

class VMRepresentation(object):
    # private scriptor class contains the necessary info for analysis
    class __Scriptor:
        def __init__(self):
            # dbg handler and trace
            self._trace = None

            # VM init values
            self._vm_operands = set()  # set of operands the vm_function gets
            self._vm_returns = dict()  # dictionary of reg:value mappings the vm_function returns
            self._vm_ctx = VMContext()
            self._vm_stack_reg_mapping = dict()

            # Env values
            self._sys_libs = False
            self._extract_param = True
            self._func_args = {}
            self._greedy = True
            self._bb = True
            self._cluster_magic = 2

            # grading automaton
            self._in_out = 2
            self._pa_ma = 2
            self._clu = 1
            self._mem_use = 3


    scriptor = None
    def __init__(self):
        # init the singleton instance
        if not VMRepresentation.scriptor:
            VMRepresentation.scriptor = VMRepresentation.__Scriptor()

    def __getattr__(self, item):
        return getattr(self.scriptor, item)

    ### trace ###
    @property
    def trace(self):
        return self.scriptor._trace

    @trace.setter
    def trace(self, value):
        self.scriptor._trace = value

    ### VM init val ###
    @property
    def code_start(self):
        return self.scriptor._vm_ctx.code_start

    @property
    def code_end(self):
        return self.scriptor._vm_ctx.code_end

    @property
    def base_addr(self):
        return self.scriptor._vm_ctx.base_addr

    @property
    def vm_addr(self):
        return self.scriptor._vm_ctx.vm_addr

    @property
    def vm_ctx(self):
        return self.scriptor._vm_ctx

    @vm_ctx.setter
    def vm_ctx(self, value):
        assert isinstance(value, VMContext)
        self.scriptor._vm_ctx = value

    @property
    def vm_operands(self):
        return self.scriptor._vm_operands

    @vm_operands.setter
    def vm_operands(self, value):
        assert isinstance(value, set)
        self.scriptor._vm_operands = value

    @property
    def vm_stack_reg_mapping(self):
        return self.scriptor._vm_stack_reg_mapping

    @vm_stack_reg_mapping.setter
    def vm_stack_reg_mapping(self, value):
        self.scriptor._vm_stack_reg_mapping = value

    @property
    def vm_returns(self):
        return self.scriptor._vm_returns

    @vm_returns.setter
    def vm_returns(self, value):
        assert isinstance(value, dict)
        self.scriptor._vm_returns = value

    ### grading automaton ###
    @property
    def in_out(self):
        return self.scriptor._in_out

    @property
    def pa_ma(self):
        return self.scriptor._pa_ma

    @property
    def clu(self):
        return self.scriptor._clu

    @property
    def mem_use(self):
        return self.scriptor._mem_use

    @in_out.setter
    def in_out(self, value):
        self.scriptor._in_out = value

    @pa_ma.setter
    def pa_ma(self, value):
        self.scriptor._pa_ma = value

    @clu.setter
    def clu(self, value):
        self.scriptor._clu = value

    @mem_use.setter
    def mem_use(self, value):
        self.scriptor._mem_use = value

    ### env ###
    @property
    def greedy(self):
        return self.scriptor._greedy

    @greedy.setter
    def greedy(self, value):
        self.scriptor._greedy = value

    @property
    def sys_libs(self):
        return self.scriptor._sys_libs

    @sys_libs.setter
    def sys_libs(self, value):
        self.scriptor._sys_libs = value

    @property
    def extract_param(self):
        return self.scriptor._extract_param

    @extract_param.setter
    def extract_param(self, value):
        self.scriptor._extract_param = value

    @property
    def func_args(self):
        return self.scriptor._func_args

    @func_args.setter
    def func_args(self, value):
        self.scriptor._func_args = value

    @property
    def bb(self):
        return self.scriptor._bb

    @bb.setter
    def bb(self, value):
        self.scriptor._bb = value

    @property
    def cluster_magic(self):
        return self.scriptor._cluster_magic

    @cluster_magic.setter
    def cluster_magic(self, value):
        self.scriptor._cluster_magic = value


class VMContext(object):
    def __init__(self):
        self.code_start = BADADDR
        self.code_end = BADADDR
        self.base_addr = BADADDR
        self.vm_addr = BADADDR

# Singelton VMR
vmr = None

def get_vmr():
    """
    Get the VMR instance.
    :return: vmr
    """
    global vmr
    if vmr is None:
        vmr = VMRepresentation()
    return vmr

def del_vmr():
    """
    Delete the VMR instance
    """
    global vmr
    vmr = None
