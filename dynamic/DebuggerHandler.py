# coding=utf-8
from dynamic.TraceRepresentation import Trace, Traceline
from lib.Logging import get_log

__author__ = 'Anatoli Kalysch'


import json

from collections import defaultdict
from copy import deepcopy
from lib.Util import remove_all_colors
from ui.UIManager import QtGui
from IDADebugger import IDADebugger

from idautils import *
from idaapi import *
from idc import *

class DebuggerHandler(object):
    def __init__(self, func=None):
        self.dbg = None
        # if function for loading the Debugger is given execute it
        if func is not None:
            self.load_dbg = types.MethodType(func, self)
            self.dbg = self.load_dbg()
        else:
            self.dbg = IDADebugger()

        if dbg_get_name() is None:
            get_log().log('[DBG] Debugger name was none so loaded default Windows32 debugger\n')
            LoadDebugger('Win32', 0)


    @property
    def check(self):
        return self.dbg is not None

    @property
    def hooked(self):
        return self.dbg.hooked

    @property
    def trace(self):
        return self._trace
    
    @trace.setter
    def trace(self, value):
        assert isinstance(value, Trace)
        self._trace = value

    def switch_debugger(self, func):
        if func is None:
            get_log().log('[DBG] Instantiation function was empty so no debugger chosen\n')
            raise Exception('[*] empty function! Cannot instantiate Debugger!')

        self.load_dbg = types.MethodType(func, self)
        self.dbg = self.load_dbg()
        self.dbg.hook_dbg()

    def gen_instruction_trace(self, start=BeginEA(), end=BADADDR):
        self._trace = Trace()
        if not self.check:
            self.dbg = self.load_dbg()
        self.dbg.hook_dbg()
        remove_all_colors()
        trace = self.dbg.gen_trace(start, end)
        self.dbg.unhook_dbg()
        return trace


def ida_offset(string):
    """
    Converts non-IDA conforming offset representation to a more IDAesk form.
    :param string: a non IDA conform string
    :return: IDA conform string
    """
    segment, rest = string.split(':', 2)
    offset_start = rest.rfind('+')
    offset = rest[offset_start + 1:-1]
    operands = rest[1:offset_start]

    # ds:off_40439c[eax * 4]
    return '%s:off_%s[%s]' % (segment, offset, operands)


def load():
    """
    Load a trace from file. Supported are IDAs txt trace files and VMAttacks json files. Further OllyDBG and ImmunityDBG traces are supported but have slightly limited analysis capabilities.
    :param path: system path to trace file
    :return: trace object
    """
    path = ''
    try:
        fd = QtGui.QFileDialog()
        fd.setFileMode(QtGui.QFileDialog.AnyFile)
        fd.setFilters(["Text files (*.txt)", "JSON files (*.json)"])
        fd.setWindowTitle('Load Trace ...')
        if fd.exec_():
            path = fd.selectedFiles()[0]
        else:
            path = None
    except:
        msg('A Problem occured with the file selector dialog, first *.txt file in the current working directory was choosen!')
        for f in os.listdir(os.getcwd()):
            if f.endswith('txt'):
                path = f
        if path == '':
            path = asktext(40, '', 'Please provide the full path to the trace file: ')

    if path is not None:
        get_log().log('[TRC] Loaded the trace at %s\n' % path)
        if path.endswith('.txt'):
            with open(path, 'r') as f:
                lines = f.readlines()
        elif path.endswith('.json'):
            with open(path) as f:
                lines = json.load(f)
        else:
            return None
        trace = Trace()

        functions = {SegName(addr): {GetFunctionName(ea): ea for ea in Functions(SegStart(addr), SegEnd(addr))} for addr in Segments()}

        try:
            context = defaultdict(lambda: False)

            # framework json trace
            if isinstance(lines, dict) or path.endswith('.json'):
                get_log().log('[TRC] The trace seems to be a VMAttack trace\n')
                for index in range(len(lines.keys())):
                    line = lines[str(index)]
                    t = Traceline(thread_id=line[0], addr=line[1], disasm=line[2], ctx=line[3], comment=line[4])
                    t.grade = line[5]
                    trace.append(t)

            # ida trace via Win32Dbg
            elif lines[0].startswith('Thread '):
                for i in lines[3:]:
                    if i.startswith('Thread'):
                        break
                    values = i.split('\t')
                    # thread id
                    thread_id = int(values[0], 16)

                    # addr
                    addr = BADADDR
                    func_name = values[1].strip(' ').split(':')
                    if len(func_name) == 2:
                        try:  # .segment:addr
                            addr = int(func_name[1], 16)
                        except:
                            try:  # .segment:func_name+offset
                                offset = int(func_name[1].split('+')[1], 16)
                                name = func_name[1].split('+')[0]
                                addr = functions[func_name[0]][name] + offset
                            except:
                                try:  # .segment:func_name-offset
                                    offset = int(i.split('-')[1].split(' ')[0], 16)
                                    name = func_name[1].split('-')[0]
                                    addr = functions[func_name[0]][name] - offset
                                except:
                                    if not func_name[1].startswith('loc_'):  # .segment:func_name
                                        addr = functions[func_name[0]][func_name[1]]
                                    else:  # .segment:jmp_location
                                        addr = int(func_name[1][4:], 16)
                    elif len(func_name) == 3:
                        addr = int(func_name[2][4:], 16)

                    # disasm
                    disasm = values[2].strip(' ').lower()
                    disasm = disasm.split('  ')
                    disasm = [x.lstrip() for x in disasm]
                    disasm = filter(None, disasm)
                    if len(disasm) > 1 and disasm[1].__contains__(', '):
                        temp = disasm.pop(1)
                        for elem in temp.split(', '):
                            disasm.append(elem.lstrip().lstrip('0').rstrip('h'))

                    # remove [ebp+0]
                    for dis in disasm:
                        if dis.__contains__('[ebp+0]'):
                            dis.replace('[ebp+0]', '[ebp]')

                    # context
                    ida_ctx = values[3].strip(' ').split(' ')
                    for value in ida_ctx:
                        try:
                            a, b = value.split('=')
                            if len(b) > 1:
                                b = ''.join(c.rstrip('\r\n') for c in b.lstrip('0'))
                            if b == '':
                                b = '0'
                            context[a.lower()] = b
                        except:
                            pass

                    trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))
            # immunity trace
            elif lines[0].startswith('Address	'):
                for i in lines[1:]:
                    if i.__contains__('Run trace closed') or i.__contains__('Process terminated'):
                        break
                    values = i.split('\t')
                    try:
                        # thread_id
                        thread_id = sum(ord(c) for c in values[1]) # immunity uses names, e.g. main
                        # addr
                        try:
                            addr = int(values[0], 16)
                        except:
                            addr = BADADDR
                        # disasm
                        disasm = values[2].lower().rstrip('\r\n')
                        disasm = disasm.split(' ', 1)
                        if len(disasm) > 1 and disasm[1].__contains__(','):
                            temp = disasm.pop(1)
                            for elem in temp.split(','):
                                disasm.append(elem.lstrip('0'))
                        disasm = [x.split('dword ptr ')[1] if x.__contains__('dword ptr ') else x for x in disasm]
                        if len(disasm) == 2 and len(re.findall(r'.*\[.*[\+\-\*].*[\+\-\*].*\].*', disasm[1])) > 0:
                            disasm[1] = ida_offset(disasm[1])
                        # context
                        if len(values) > 3:
                            olly_ctx = values[3].lstrip(' ').rstrip('\r\n').split(',')
                            for value in olly_ctx:
                                try:
                                    a, b = value.split('=')
                                    if len(b) > 1:
                                        b = ''.join(c for c in b.lstrip('0') if c not in '\n\r\t')
                                    if b == '':
                                        b = '0'
                                    context[a.lower()] = b
                                except:
                                    pass
                        trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))
                    except:
                        if i.__contains__('terminated') or i.__contains__('entry point'):
                            pass

            # olly trace
            elif lines[1].startswith('main	'):
                for i in lines[1:]:
                    if i.__contains__('Logging stopped'):
                        break
                    values = i.split('\t')
                    # thread_id
                    thread_id = sum(ord(c) for c in values[0])  # olly uses names, e.g. main
                    # addr
                    try:
                        addr = int(values[1], 16)
                    except:
                        addr = BADADDR
                    # disasm
                    disasm = values[2].lower().rstrip('\r\n')
                    disasm = disasm.split(' ', 1)
                    if len(disasm) > 1 and disasm[1].__contains__(','):
                        temp = disasm.pop(1)
                        for elem in temp.split(','):
                            disasm.append(elem.lstrip('0'))

                    disasm = [x.split('dword ptr ')[1] if x.__contains__('dword ptr ') else x for x in disasm]
                    if len(disasm) == 2 and len(re.findall(r'.*\[.*[\+\-\*].*[\+\-\*].*\].*', disasm[1])) > 0:
                        disasm[1] = ida_offset(disasm[1])
                    # context
                    if len(values) > 3:
                        olly_ctx = values[3].lstrip(' ').rstrip('\r\n').split(',')
                        for value in olly_ctx:
                            try:
                                a, b = value.split('=')
                                if len(b) > 1:
                                    b = ''.join(c for c in b.lstrip('0') if c not in '\n\r\t')
                                if b == '':
                                    b = '0'
                                context[a.lower()] = b
                            except:
                                pass
                    trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))


            if 'rax' in trace[-1].ctx.keys():
                trace.ctx_reg_size = 64
            elif 'eax' in trace[-1].ctx.keys() and 'rax' not in trace[-1].ctx.keys():
                trace.ctx_reg_size = 32
            msg("[*] Trace Loaded!\n")
            return trace
        except Exception, e:
            raise Exception('[*] Exception occured: \n%s\n' % (e.message))
    else:
        return None


def save(trace):
    try:
        fd = QtGui.QFileDialog()
        fd.setFileMode(QtGui.QFileDialog.AnyFile)
        fd.setFilter('JSON Files (*.json)')
        fd.setWindowTitle('Save Trace ...')
        if fd.exec_():
            path = fd.selectedFiles()[0]
        else:
            path = None
    except:
        path = os.getcwd() + get_root_filename() + '_trace_%s.json' % time.time()

    if path is not None:
        if path.endswith('.json'):
            path = path[:-5]
        with open(path + '.json', 'w') as f:
            if trace:
                obj = {i:['%x' % trace[i].thread_id,
                          '%x' % trace[i].addr,
                          trace[i].disasm,
                          trace[i].ctx,
                          trace[i].comment,
                          trace[i].grade] for i in range(len(trace))}
                f.write(json.dumps(obj))
                msg('[*] Trace saved!\n')
            else:
                raise Exception("[*] Trace seems to be None:\n %s" % trace)

# Singelton DebuggerHandler
dbg_handl = None

def get_dh(choice=None):
    global dbg_handl
    if dbg_handl is None:
        dbg_handl = DebuggerHandler(choice)
    return dbg_handl