# coding=utf-8
from copy import deepcopy

from lib.VMRepresentation import get_vmr

__author__ = 'Anatoli Kalysch'

from Debugger import Debugger
from dynamic.TraceRepresentation import Trace, Traceline
from idaapi import *
from lib.Util import *
from _collections import defaultdict
from lib.Util import get_reg_class, get_reg


class IDADebugger(DBG_Hooks, Debugger):
    def __init__(self, *args):
        super(IDADebugger, self).__init__(*args)
        self.hooked = False
        self.trace = Trace()
        self._module_name = 'IDADbg'
        self.arch = get_arch_dynamic()
        # init the cpu context with 0
        if self.arch == 32:
            self.ctx = {c: '0' for c in ['eax', 'ebx', 'edx', 'ecx', 'ebp', 'esp', 'eip', 'edi', 'esi', 'cf', 'zf', 'sf', 'of', 'pf',
                         'af', 'tf', 'df']}
        elif self.arch == 64:
            self.ctx = {c: '0' for c in ['rax', 'rbx', 'rdx', 'rcx', 'rbp', 'rsp', 'rip', 'edi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12',
                         'r13', 'r14', 'r15', 'cf', 'zf', 'sf', 'of', 'pf', 'af', 'tf', 'df']}

        self.IAT = []
        self.func_args = defaultdict(lambda: set())

    @property
    def module_name(self):
        return self._module_name

    def convert(self, value):
        """
        Convert a value into its hex representation.
        :param value:
        :return:
        """
        result = '%x' % int(value)
        return result.upper()

    def disconv(self, value):
        """
        Convert the DISASM to a standardized representation. This enables the equivalence between generated traces and loaded traces.
        :param value: a disasm str
        :return: standardized str
        """
        # disregard comments
        if value.__contains__(';'):
            value = value.split(';')[0]
        disasm = value.lower().split('  ')


        disasm = [x.lstrip() for x in disasm]
        disasm = filter(None, disasm)
        if len(disasm) > 1 and disasm[1].__contains__(', '):
            temp = disasm.pop(1)
            for elem in temp.split(', '):
                disasm.append(elem.lstrip().lstrip('0').rstrip('h'))

        return disasm

    def trace_init(self):
        """
        Init the trace.
        """
        if self.arch is None:
            self.arch == get_arch_dynamic()
        # reset trace
        self.trace = Trace(reg_size=self.arch)

    def hook_dbg(self):
        if self.hooked:  # Release any current hooks
            self.unhook()

        try:
            # check if ida dbg is present and ready
            if not dbg_can_query():
                return

            # hook IDADebugger
            self.hook()
            self.hooked = True
            self.arch = get_arch_dynamic()

        except Exception as ex:
            print "An Exception was encountered: %s" % ex.message

    def get_new_color(self, current_color):
        """
        Redistribute a new color to a line.
        :param current_color: the current color of a line
        :return: the next or the max color
        """
        colors = [0xffe699, 0xffcc33, 0xe6ac00, 0xb38600]
        try:
            index = colors.index(current_color)
            if index == len(colors) - 1:
                return colors[-1]
            else:
                return colors[index + 1]
        except ValueError:
            return colors[0]

    # TODO IAT checks
    def gen_trace(self, trace_start=BeginEA(), trace_end=BADADDR):
        """
        Generate trace for the loaded binary.
        :param trace_start:
        :param trace_end:
        :return:
        """
        vmr = get_vmr()
        self.trace_init()
        # reset color
        heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
        for i in heads:
            SetColor(i, CIC_ITEM, 0xFFFFFF)
        # start exec
        RunTo(BeginEA())
        event = GetDebuggerEvent(WFNE_SUSP, -1)
        # enable tracing
        EnableTracing(TRACE_STEP, 1)
        if vmr.sys_libs:
            pass
        event = GetDebuggerEvent(WFNE_ANY | WFNE_CONT, -1)
        while True:
            event = GetDebuggerEvent(WFNE_ANY, -1)
            addr = GetEventEa()

            # change color of executed line
            current_color = GetColor(addr, CIC_ITEM)
            new_color = self.get_new_color(current_color)
            SetColor(addr, CIC_ITEM, new_color)
            # break by exception
            if event <= 1:
                break

        # standardize the difference between ida_trace.txt files and generated trace files by debugger hook:
        # since dbg_trace returns the cpu context before the instruction execution and trace files the ctx after
        for line in self.trace:
            try:
                line.ctx = self.trace[self.trace.index(line) + 1].ctx
            except IndexError:
                line.ctx = defaultdict(lambda: '0')
        # return the trace, for population see dbg_trace() below
        msg('[*] Trace generated!\n')
        if vmr.extract_param:
            vmr.func_args = self.func_args
            for key in self.func_args.keys():
                print 'Function %s call args:' % key, ''.join('%s, ' % arg for arg in self.func_args[key]).rstrip(', ')
        return self.trace

    def unhook_dbg(self):
        if self.hooked:
            # unhook IDADebugger
            self.unhook()
            self.hooked = False
        else:
            pass

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        # print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        pass

    def dbg_process_exit(self, pid, tid, ea, code):
        # print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        pass

    def dbg_library_unload(self, pid, tid, ea, info):
        print("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        return 0

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        # print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        pass

    def dbg_process_detach(self, pid, tid, ea):
        # print("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)


    def dbg_bpt(self, tid, ea):
        # print "Break point at 0x%x pid=%d" % (ea, tid)
        # self.tid = tid
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0

    def dbg_suspend_process(self):
        # print "Process suspended"
        pass

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (pid, tid, ea, exc_code & BADADDR, exc_can_cont, exc_ea, exc_info))
        # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        return 0

    def dbg_trace(self, tid, ea):
        """

        :param tid:
        :param ea:
        :return:
        """
        vmr = get_vmr()
        try:
            if vmr.extract_param and GetDisasm(ea).__contains__('call'):
                run_var = 0
                key = GetDisasm(ea).split('call')[1].strip()
                while True:
                    # traverse trace backwards and get sequential push and mov params
                    line = self.trace[-(run_var + 1)]
                    if line.is_push and line.disasm_len == 2:
                        try:
                            self.func_args[key].add(line.ctx[get_reg(line.disasm[1], self.arch)])
                        except:
                            self.func_args[key].add(line.disasm[1])
                    elif line.is_mov:
                        try:
                            self.func_args[key].add(line.ctx[get_reg(line.disasm[2], self.arch)])
                        except:
                            self.func_args[key].add(line.disasm[2])
                    else:
                        break
                    run_var += 1
            # TODO mmx xmmx ymmx
            # compute next ctx
            if self.arch == 32:
                self.ctx = defaultdict(lambda: '0', {'eax': self.convert(cpu.eax), 'ebx': self.convert(cpu.ebx), 'edx': self.convert(cpu.edx), 'ecx': self.convert(cpu.ecx),
                            'ebp': self.convert(cpu.ebp), 'esp': self.convert(cpu.esp), 'eip': self.convert(cpu.eip), 'edi': self.convert(cpu.edi),
                            'esi': self.convert(cpu.esi), 'cf': self.convert(cpu.cf), 'zf': self.convert(cpu.zf), 'sf': self.convert(cpu.sf),
                            'of': self.convert(cpu.of), 'pf': self.convert(cpu.pf), 'af': self.convert(cpu.af), 'tf': self.convert(cpu.tf),
                            'df': self.convert(cpu.df)})
            elif self.arch == 64:
                self.ctx = defaultdict(lambda: '0', {'rax': self.convert(cpu.eax), 'rbx': self.convert(cpu.ebx), 'rdx': self.convert(cpu.edx), 'rcx': self.convert(cpu.ecx),
                            'rbp': self.convert(cpu.ebp), 'rsp': self.convert(cpu.esp), 'rip': self.convert(cpu.eip), 'edi': self.convert(cpu.edi),
                            'rsi': self.convert(cpu.rsi), 'r8': self.convert(cpu.r8), 'r9': self.convert(cpu.r9), 'r10': self.convert(cpu.r10),
                            'r11': self.convert(cpu.r11), 'r12': self.convert(cpu.r12), 'r13': self.convert(cpu.r13), 'r14': self.convert(cpu.r14),
                            'r15': self.convert(cpu.r15), 'cf': self.convert(cpu.cf), 'zf': self.convert(cpu.zf), 'sf': self.convert(cpu.sf),
                            'of': self.convert(cpu.of), 'pf': self.convert(cpu.pf), 'af': self.convert(cpu.af), 'tf': self.convert(cpu.tf),
                            'df': self.convert(cpu.df)})

            self.trace.append(Traceline(thread_id=tid, addr=ea, disasm=self.disconv(GetDisasm(ea)), ctx=deepcopy(self.ctx)))
        except Exception, e:
            print e.message
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        return 0
