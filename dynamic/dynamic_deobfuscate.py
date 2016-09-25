# coding=utf-8

__author__ = 'Anatoli Kalysch'

from threading import Thread

from ui.UIManager import GradingViewer
from ui.UIManager import OptimizationViewer
from ui.UIManager import StackChangeViewer
from ui.UIManager import VMInputOuputViewer

from DebuggerHandler import load, save, get_dh
from lib.TraceAnalysis import *
from lib.VMRepresentation import get_vmr
from ui.NotifyProgress import NotifyProgress
from ui.UIManager import ClusterViewer


### DEBUGGER LOADING STRATEGIES ###
# IDA Debugger
def load_idadbg(self):
    from IDADebugger import IDADebugger
    return IDADebugger()

# OllyDbg
def load_olly(self):
    from OllyDebugger import OllyDebugger
    return OllyDebugger()

# Bochs Dbg
def load_bochsdbg(self):
    from IDADebugger import IDADebugger
    LoadDebugger('Bochs', 0)
    return IDADebugger()

# Win32 Dbg
def load_win32dbg(self):
    from IDADebugger import IDADebugger
    LoadDebugger('win32', 0)
    return IDADebugger()

# Immunity Dbg
def load_immunitydbg(self):
    from IDADebugger import IDADebugger
    return IDADebugger()


# Working with Win32Dbg, BochsDbg, OllyDbg
available_debuggers = [load_idadbg, load_olly, load_bochsdbg, load_win32dbg, load_immunitydbg]


### INIT AND LOAD CONTEXT ###

def prepare_trace():
    vmr = get_vmr()
    if vmr.trace is None:
        vmr.trace = load()
    return deepcopy(vmr.trace)

def prepare_vm_ctx():
    vmr = get_vmr()
    return deepcopy(vmr.vm_ctx)

def prepare_vm_operands():
    vmr = get_vmr()
    return deepcopy(vmr.vm_operands)

def load_dbg(choice):
    dbg_handl = get_dh(available_debuggers[choice])
    if dbg_handl.check:
        return dbg_handl
    else:
        raise Exception("[*] Could not load debugger! Please check if the selected debugger is available.")

def load_trace():
    vmr = get_vmr()
    trace = load()
    vmr.trace = trace

def save_trace():
    trace = prepare_trace()
    save(trace)

def gen_instruction_trace(choice):
    """
    Generate instruction trace
    :param choice: which debugger to use
    """
    dbg_handl = get_dh(choice)
    vmr = get_vmr()
    trace = dbg_handl.gen_instruction_trace()
    if trace is not None:
        vmr.trace = trace
    else:
        raise Exception('[*] Trace seems to be None, so it was disregarded!')

### ANALYSIS FUNCTIONALITY###
# TODO multithreading !!!
class DynamicAnalyzer(Thread):
    def __init__(self, func, trace, **kwargs):
        super(DynamicAnalyzer, self).__init__()
        self.analysis = func
        self.trace = deepcopy(trace)
        self.kwargs = kwargs
        self.result = None

    def run(self):
        self.result = self.analysis(self.trace, self.kwargs)

    def get_result(self):
        return self.result


def address_heuristic():
    """
    Compute the occurrence of every address in the instruction trace.
    """
    w = NotifyProgress('Address count')
    w.show()
    try:
        trace = prepare_trace()
        w.pbar_update(40)
        ac = address_count(deepcopy(trace))
        w.pbar_update(60)
        w.close()

        for addr, count in ac:
            print 'Address %x (Disasm: %s) was encountered %s times.' % (addr, GetDisasm(addr), count)
    except:
        print '[*] An exception occurred! Quitting! '
        w.close()

# analysis functions supporting manual flag
manual_func = [find_output, find_input, find_virtual_regs, follow_virt_reg]
def manual_analysis(choice):
    """
    Allows the execution of analysis functions with the manual flag. Output will mainly be in the Output window and some instances require user interaction.
    :param choice: the manual function to be executed
    """
    w = NotifyProgress('Address count')
    w.show()
    trace = prepare_trace()
    func = manual_func[choice]
    w.pbar_update(10)
    func(deepcopy(trace), manual=True, update=w)
    w.close()

def input_output_analysis(manual=False):
    """
    Input / Output analysis wrapper which computes the components of the output values of the VM function and allows for comparing these with the input arguments to the VM function.
    Afterwards the results are presented in the VMInputOutputViewer.
    :param manual: let user choose Function for input output analysis
    """
    func_addr = None
    if manual:
        func_addr = ChooseFunction('Please select the function for black box analysis')
    w = NotifyProgress('In/Out')
    w.show()

    trace = prepare_trace()
    vmr = get_vmr()
    # find relevant regs and operands
    ctx = {}
    try:
        if func_addr is not None:  # TODO enable input / output analysis of all functions
            input = find_input(deepcopy(trace))
            output = find_output(deepcopy(trace))
            w.close()
        else:
            vr = DynamicAnalyzer(find_virtual_regs, trace)
            w.pbar_update(10)
            vr.start()
            input = DynamicAnalyzer(find_input, trace)
            w.pbar_update(10)
            input.start()
            output = DynamicAnalyzer(find_output, trace)
            w.pbar_update(10)
            output.start()
            vr.join()
            w.pbar_update(20)
            vr = vr.get_result()
            # create the trace excerpt for every relevant reg
            for key in vr.keys():
                if get_reg_class(key) is not None:
                    ctx[key] = follow_virt_reg(deepcopy(trace), virt_reg_addr=vr[key], real_reg_name=key)
            vmr.vm_stack_reg_mapping = ctx
            w.pbar_update(20)
            input.join()
            w.pbar_update(10)
            output.join()
            w.pbar_update(10)

            w.close()
            v = VMInputOuputViewer(input.get_result(), output.get_result(), ctx)
            v.Show()
    except:
        w.close()

def clustering_analysis(visualization=0, grade=False, trace=None):
    """
    Clustering analysis wrapper which clusters the trace into repeating instructions and presents the results in the Clustering Viewer.
    :param visualization: output via Clustering Viewer or output window
    :param grade: grading
    :param trace: instruction trace
    """
    if trace is None:
        trace = prepare_trace()

    w = NotifyProgress('Clustering')
    w.show()

    try:
        try:
            if not trace.constant_propagation:
                trace = optimization_const_propagation(trace)
            if not trace.stack_addr_propagation:
                trace = optimization_stack_addr_propagation(trace)
        except:
            pass
        w.pbar_update(30)
        # cluster
        vr = find_virtual_regs(deepcopy(trace))
        w.pbar_update(20)
        cluster = repetition_clustering(deepcopy(trace))
        w.pbar_update(25)
        if visualization == 0:

            v0 = ClusterViewer(cluster, create_bb_diff, trace.ctx_reg_size, save_func=save)
            w.pbar_update(24)
            v0.Show()

            prev_ctx = defaultdict(lambda: 0)
            stack_changes = defaultdict(lambda: 0)
            for line in cluster:
                if isinstance(line, Traceline):
                    prev_ctx = line.ctx
                else:
                    stack_changes = create_cluster_gist(line, trace.ctx_reg_size, prev_ctx, stack_changes)
                    prev_ctx = line[-1].ctx
            # sort the stack_changes by address
            sorted_result = sorted(stack_changes.keys())
            sorted_result.reverse()
            w.close()
            v1 = StackChangeViewer(vr, sorted_result, stack_changes)
            v1.Show()
        else:
            w.close()
            visualize_cli(cluster)
    except:
        w.close()

def optimization_analysis():
    """
    Opens the Optimization Viewer to let the user dynamically interact with the trace.
    """
    trace = prepare_trace()
    v = OptimizationViewer(trace, save=save)
    v.Show()

def dynamic_vmctx(manual=False):
    """
    Compute the VM context values based on the trace.
    :param manual: output in output window
    """
    trace = prepare_trace()
    vm_ctx = dynamic_vm_values(trace)
    vmr = get_vmr()
    vmr.vm_ctx = vm_ctx
    if manual:
        print 'Code Start: %x; Code End: %x; Base Addr: %x; VM Addr: %x' % (vm_ctx.code_start, vm_ctx.code_end, vm_ctx.base_addr, vm_ctx.vm_addr)

def init_grading(trace):
    """
    Grading System initialization. This function is part of the automaton grading system.
    High grade equals importance. The higher the better. This is the initialization routine for the grading automaton. It assigns the initial grade according to the uniqueness of a line.
    :param trace: instruction trace
    """
    addr_count = address_count(deepcopy(trace))
    grade = len(set(i[1] for i in addr_count))
    addr_count.reverse()  # now the addrs with single occurence are at the beginning of the list
    ctr = 1
    for tupel in addr_count:  # tupel[0] == address, tupel[1] == address occurence
        if ctr != tupel[1]:
            ctr = tupel[1]
            grade -= 1

        for line in trace:
            if line.addr == tupel[0]:
                line.grade = grade
    return trace


def grading_automaton(visualization=0):
    """
    Grading System Analysis computes a grade for every trace line. It is basically a combination of all available analysis capabilities and runs them one after another, increases the grade
    for those trace lines which are in the analysis result and then runs the next trace analysis. In between the analysis runs a pattern matching run is started, to increase / decrease cer-
    tain trace lines grades based on known patterns. The patterns are modelled after known short comings of the analysis capabilities.
    :param trace: instruction trace
    :return: graded instruction trace
    """
    vmr = get_vmr()

    w = NotifyProgress('Grading')
    w.show()

    trace = prepare_trace()
    try:
        ### INIT THE TRACE GRADES ###
        trace = init_grading(deepcopy(trace))
        w.pbar_update(10)

        ### REGISTER USAGE BASED: this must be done before optimization
        reg_dict = defaultdict(lambda: 0)

        # find the register infrastructure and vm addressing scheme -> this tells us which registers are used for addressing and are not important for grading_automaton
        for line in trace:
            assert isinstance(line, Traceline)
            if line.is_op2_reg and get_reg_class(line.disasm[2]) is not None:  # get reg class will only return != None for the 8-16 standard cpu regs
                reg_dict[get_reg_class(line.disasm[2])] += 1

        # get the sorted list of regs highest occurence first
        sorted_keys = sorted(reg_dict.items(), key=operator.itemgetter(1), reverse=True)  # sorted_list = list of (reg_name, frequency)
        length = len(sorted_keys)
        w.pbar_update(10)
        # classify the important and less important registers
        if length % 2 == 0:
            important_regs = set(reg[0] for reg in sorted_keys[:(length / 2)])
            disregard_regs = set(reg[0] for reg in sorted_keys[(length / 2):])
        else:
            # if this is the case, one more register gets declared unimportant, since it is better to be more careful about raising grades
            important_regs = set(reg[0] for reg in sorted_keys[:(length - 1) / 2])
            disregard_regs = set(reg[0] for reg in sorted_keys[(length - 1) / 2:])

        ### OPTIMIZE TRACE ###
        try:
            if not trace.constant_propagation:
                trace = optimization_const_propagation(trace)
        except:
            pass
        w.pbar_update(10)
        try:
            if not trace.stack_addr_propagation:
                trace = optimization_stack_addr_propagation(trace)
        except:
            pass

        ### REGISTER USAGE AND INPUT OUTPUT BASED ###
        # raise the grade of line containing input and output values
        values = find_input(deepcopy(trace)).union(find_output(deepcopy(trace)))
        for line in trace:
            for val in values:
                if val in line.to_str_line():
                    line.raise_grade(vmr.in_out)

        w.pbar_update(10)

        # backtrace regs and raise grade
        virt_regs = find_virtual_regs(deepcopy(trace))
        for key in virt_regs:
            if get_reg_class(key) in important_regs:
                for line in follow_virt_reg(deepcopy(trace), virt_reg_addr=virt_regs[key]):
                    try:
                        for other in trace:
                            if line == other:
                                other.raise_grade(vmr.in_out)
                    except ValueError:
                        print 'The line %s was not found in the trace, hence the grade could not be raised properly!' % line.to_str_line()
            elif get_reg_class(key) in disregard_regs:
                for line in follow_virt_reg(deepcopy(trace), virt_reg_addr=virt_regs[key]):
                    try:
                        for other in trace:
                            if line == other:
                                other.lower_grade(vmr.in_out)
                    except ValueError:
                        print 'The line %s was not found in the trace, hence the grade could not be lowered properly!' % line.to_str_line()
        w.pbar_update(5)

        ### REGISTER USAGE FREQUENCY BASED ###
        # lower the grades for the most commonly used registers
        for line in trace:
            assert isinstance(line, Traceline)
            if line.is_op1_reg and get_reg_class(line.disasm[1]) is not None:  # get reg class will only return != None for the 8-16 standard cpu regs
                reg_dict[get_reg_class(line.disasm[1])] += 1

        # get the sorted list of regs highest occurrence first
        sorted_keys = sorted(reg_dict.items(), key=operator.itemgetter(1), reverse=True)  # sorted_list = list of (reg_name, frequency)
        length = len(sorted_keys)
        w.pbar_update(5)
        # classify the less important registers
        if length % 2 == 0:
            disregard_regs = set(reg[0] for reg in sorted_keys[:(length / 2)])
        else:
            disregard_regs = set(reg[0] for reg in sorted_keys[:(length - 1) / 2])


        for line in trace:
            assert isinstance(line, Traceline)
            if line.is_jmp or line.is_mov or line.is_pop or line.is_push or line.disasm[0].startswith('ret') or line.disasm[
                0].startswith('inc') or line.disasm[0].startswith('lea'):
                line.lower_grade(vmr.pa_ma)
            elif len(line.disasm) > 1 and get_reg_class(line.disasm[1]) in disregard_regs:
                line.lower_grade(vmr.pa_ma)
        w.pbar_update(10)

        ### CLUSTERING BASED ###
        # raise the grades of the unique lines after clustering
        cluster_result = repetition_clustering(deepcopy(trace))
        for line in cluster_result:
            if isinstance(line, Traceline):
                trace[trace.index(line)].raise_grade(vmr.clu)
        w.pbar_update(10)

        ### PEEPHOLE GRADING ###
        # peephole grading
        for line in trace:
            assert isinstance(line, Traceline)
            if line.disasm[0] in ['pop', 'push', 'inc', 'dec', 'lea', 'test'] or line.disasm[0].startswith('c') or line.is_jmp or line.is_mov or line.disasm[0].startswith('r'):
                line.lower_grade(vmr.pa_ma)
            elif len(line.disasm) > 1 and get_reg_class(line.disasm[1]) > 4:
                continue
            else:
                line.raise_grade(vmr.pa_ma)

        w.pbar_update(10)

        ### OPTIMIZATION BASED ###
        opti_trace = optimize(deepcopy(trace))
        w.pbar_update(10)
        for line in opti_trace:
            assert isinstance(line, Traceline)
            try:  # trace is heavily changed after optimization, might not find the trace line in the pre_op_trace
                trace[trace.index(line)].raise_grade(vmr.pa_ma)
            except:
                pass
            # additionally raise grade for every line that uses the memory and is not a mov
            if line.disasm_len == 3 and line.is_op1_mem and not line.is_mov:
                try:
                    trace[trace.index(line)].raise_grade(vmr.mem_use)
                except:
                    pass
            else:
                trace[trace.index(line)].lower_grade(vmr.pa_ma)

        w.pbar_update(5)

        ### STATIC OPTIMIZATION BASED ###
        # TODO atm this is a little workaround to include the static analysis results
        try:
            comments = set(v_inst.split(' ')[0] for v_inst in [Comment(ea) for ea in range(vmr.code_start, vmr.code_end)] if v_inst is not None)
            print comments
            ins = [c.lstrip('v').split('_')[0] for c in comments]
            print ins
            for line in trace:
                if line.disasm[0] in ins:
                    line.raise_grade(vmr.static)
                    print line.to_str_line()

        except:
            pass
        w.pbar_update(5)
        w.close()

        grades = set([line.grade for line in trace])
        if visualization == 0:
            v = GradingViewer(trace, save=save)
            v.Show()
        else:
            threshold = AskLong(1, 'There are a total of %s grades: %s. Specify a threshold which lines to display:' % (len(grades), ''.join('%s ' % c for c in grades)))
            if threshold > -1:
                for line in trace:
                    if line.grade >= threshold:
                        print line.grade, line.to_str_line()

    except Exception, e:
        w.close()
        msg(e.message + '\n')