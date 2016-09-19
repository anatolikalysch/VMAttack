# coding=utf-8
from collections import defaultdict

__author__ = 'Anatoli Kalysch'

from dynamic.TraceRepresentation import Trace, Traceline
from lib.Util import *

#######################################
### OPTIMIZATION AND RELATED FUNC   ###
#######################################
"""Propagations should be always save to use, as they do not leave out anything. Foldings should be used with care, as
they leave out lines deemed unuseful and as such might leave out too much."""

def optimization_peephole_folding(trace):
    """
    Peephole optimizations take identified patterns and use them on the trace. Can be powerful, but patterns have to be identified manually first.
    TODO peephole will be improved with new patterns
    :param trace:
    :return:
    """
    kill_index = []

    # frequency based peephole - remove the one most common address cluster, since it will most certainly be part of the handler
    addrs = [line.addr for line in trace]
    addrs = {addr: addrs.count(addr) for addr in addrs}
    max_val = max(set(addrs.values()))
    # this method will work even if the handler consists of several basic blocks, as long as they have the same occurrence frequency in the trace
    kill_index.extend([line for line in trace if line.addr in [addrs[key] for key in addrs.keys() if addrs[key] == max_val]])

    for line in trace:
        #start instruction based peephole
        assert isinstance(line, Traceline)
        try:
            next_line = trace[trace.index(line) + 1]
        except:
            next_line = None
        try:
            prev_line = trace[trace.index(line) - 1]
        except:
            prev_line = None


        ### optimizations for inst with 2 operands
        if len(line.disasm) == 3:
            # case mov reg, reg following movzx/movsx reg, reg
            if line.is_mov and line.is_op1_reg and line.is_op2_reg:
                if next_line.is_mov and next_line.is_op1_reg and next_line.is_op2_reg and (get_reg_class(next_line.disasm[1]) == get_reg_class(line.disasm[1])):
                    disasm_replacement = [next_line.disasm[0], next_line.disasm[1], line.disasm[2]]
                    line.disasm = disasm_replacement
                    kill_index.append(next_line)

        ### optimizations for inst with 1 operand
        elif len(line.disasm) == 2:
            if line.disasm[0].startswith('inc') and get_reg_class(line.disasm[1]) > 4:
                kill_index.append(line)
            elif line.disasm[0].startswith('dec') and get_reg_class(line.disasm[1]) > 4:
                kill_index.append(line)

        ### optimizations for inst with no operand
        elif len(line.disasm) == 1:
            pass

        if line is not None and next_line is not None and prev_line is not None:
            if line.addr == next_line.addr == prev_line.addr:
                if line not in kill_index:
                    kill_index.append(line)
            if line.disasm[0] == prev_line.disasm[0] == next_line.disasm[0]:
                if line not in kill_index:
                    kill_index.append(line)

    # prev optimization dependant optimizations
    if trace.constant_propagation and trace.stack_addr_propagation:
        for line in trace:
            # after the propagation optimizations we can remove stack to register interaction (but *not* the register to stack)
            if line.is_mov and line.is_op1_reg and line.is_op2_mem:
                kill_index.append(line)

    # remove the unuseful declared lines from the trace
    for line in set(kill_index):  # set to remove duplicates which would throw ValueErrors
        trace.pop(trace.index(line))

    trace.peephole = True

    return trace


def optimization_const_propagation(trace):
    """
    Otimization replacing register names or computing and replacing memory locations in the trace with their known values.
    :param trace: Trace object
    :return: optimized trace
    """
    for line in trace:
        index = trace.index(line)
        if index == 0:
            prev_line = line
        else:
            prev_line = trace[trace.index(line)-1]


        # inst and 2 operands
        if len(line.disasm) == 3:
            # inst eax ax
            if get_reg_class(line.disasm[1]) is not None and get_reg_class(line.disasm[2]) is not None and get_reg_class(line.disasm[1]) == get_reg_class(line.disasm[2]):
                line.disasm[2] = line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]
            # inst op1 reg
            elif get_reg_class(line.disasm[2]) is not None:
                line.disasm[2] = prev_line.ctx[get_reg(line.disasm[2], trace.ctx_reg_size)]
            # inst op1 [reg] or inst op1 [reg +/-/... reg]
            elif line.disasm[2].startswith('[') and line.disasm[2].endswith(']'):
                try:
                    expr = re.findall(r'\[.*([\+\-\*]).*\]', line.disasm[2])[0]  # find math expr + or - or * or /
                    elem = line.disasm[2].split(expr)
                    exception_list = []
                    operand_list = []
                    for e in elem:
                        e = ''.join(c for c in e if c not in '[]hL')
                        try:
                            if get_reg_class(e) is not None:
                                operand_list.append(int(prev_line.ctx[get_reg(e, trace.ctx_reg_size)], 16))
                            else:
                                operand_list.append(int(sanitize_hex(e), 16))
                        except:
                            exception_list.append(expr)
                            exception_list.append(e)

                    result = interprete_math_expr(operand_list, expr)

                    line.disasm[2] = '[' + hex(result).lstrip('0x').upper() + ''.join(c for c in exception_list) + ']'
                except:  # if it fails, we are in case inst op1 [reg]
                    if get_reg_class(line.disasm[2][1:-1]) is not None:
                        line.disasm[2] = prev_line.ctx[get_reg(line.disasm[2][1:-1], trace.ctx_reg_size)]
            # inst op1 byte/word/other ptr [reg]
            elif line.disasm[2].__contains__('ptr'):
                try:
                    reg = re.findall(r'.*ptr \[(.*)\]', line.disasm[2])[0]
                    if reg.__contains__('+0'):
                        reg.replace('+0','')
                    replacement = prev_line.ctx[get_reg(reg, trace.ctx_reg_size)]
                    line.disasm[2] = re.findall(r'(.*ptr \[).*', line.disasm[2])[0] + replacement + ']'
                except:
                    pass
            # int op1 xs:[reg]
            elif line.disasm[2].__contains__('s:[') and line.disasm[2].endswith(']'):
                try:
                    line.disasm[2] = '[%s]' % prev_line.ctx[get_reg(re.findall(r'.*s:\[(.*)\]', line.disasm[2])[0], trace.ctx_reg_size)]
                except:
                    pass
            # inst reg op2 should not be replaced since it harms readability
            if get_reg_class(line.disasm[2]) is not None and 'cmp' == line.disasm[0]:
                line.disasm[1] = prev_line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]
            # inst [reg] op2 or inst [reg or mem +/-/... reg or mem] op2
            elif line.disasm[1].startswith('[') and line.disasm[1].endswith(']'):
                try:
                    expr = re.findall(r'\[.*([\+\-\*\/]).*\]', line.disasm[1])[0]  # find math expr + or - or *
                    elem = line.disasm[1].split(expr)
                    exception_list = []
                    operand_list = []
                    for e in elem:
                        e = ''.join(c for c in e if c not in '[]hL')
                        try:
                            if get_reg_class(e) is not None:
                                operand_list.append(int(prev_line.ctx[get_reg(e, trace.ctx_reg_size)], 16))
                            else:
                                operand_list.append(int(sanitize_hex(e), 16))
                        except:
                            exception_list.append(expr)
                            exception_list.append(e)

                    result = interprete_math_expr(operand_list, expr)

                    line.disasm[1] = '[' + hex(result).lstrip('0x').upper() + ''.join(c for c in exception_list) + ']'
                except:  # if it fails, we are in case inst [reg] op2
                    if get_reg_class(line.disasm[1][1:-1]) is not None:
                        line.disasm[1] = prev_line.ctx[get_reg(line.disasm[1][1:-1], trace.ctx_reg_size)]
            # inst byte/word/other ptr [reg], op2
            elif line.disasm[1].__contains__('ptr'):
                try:
                    reg = re.findall(r'.*ptr \[(.*)\]', line.disasm[1])[0]
                    if reg.__contains__('+0'):
                        reg.replace('+0', '')
                    replacement = prev_line.ctx[get_reg(reg, trace.ctx_reg_size)]
                    line.disasm[1] = re.findall(r'(.*ptr \[).*', line.disasm[1])[0] + replacement + ']'
                except:
                    pass
        elif len(line.disasm) == 2:
            if line.disasm[1].endswith(']'):
                try:
                    op = re.findall(r'.*\[(.*)\].*', line.disasm[1])[0]

                    # inst [reg]
                    if get_reg_class(op) is not None:
                        line.disasm[1].replace('[%s]' % op, get_reg(op, trace.ctx_reg_size))
                    # inst [mem] disregarded, since mem is already a constant
                    else:
                        # inst [reg*/+/-off] or inst [mem*/-/+off]
                        expr = re.findall(r'\[.*([\+\-\*\/]).*\]', line.disasm[1])[0]  # find math expr + or - or * or /
                        result = 0
                        elem = op.split(expr)
                        exception_list = []
                        operand_list = []
                        for e in elem:
                            e = ''.join(c for c in e if c not in '[]hL')
                            try:
                                if get_reg_class(e) is not None:
                                    operand_list.append(int(prev_line.ctx[get_reg(e, trace.ctx_reg_size)], 16))
                                else:
                                    operand_list.append(int(sanitize_hex(e), 16))
                            except:
                                exception_list.append(expr)
                                exception_list.append(e)

                        result = interprete_math_expr(operand_list, expr)
                        pre = re.findall(r'(.*\[).*', line.disasm[1])[0]
                        line.disasm[1] = pre + hex(result).lstrip('0x').upper() + ''.join(c for c in exception_list if len(exception_list) > 1) + ']'
                except:
                    pass

            # inst reg
            # elif get_reg_class(line.disasm[1]) is not None and line.disasm[0] not in ['pop', 'push']:
            #     line.disasm[1] = prev_line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]


    trace.constant_propagation = True

    return trace


def optimization_standard_ops_folding(trace):
    """
    Optimization changes certain operations into other, more standardized operations. This enables readability and pattern recognition.
    TODO standardization will be improved with new patterns
    :param trace:
    :return:
    """
    if not trace.constant_propagation:
        trace = optimization_const_propagation(trace)
    if not trace.stack_addr_propagation:
        trace = optimization_stack_addr_propagation(trace)
    for line in trace:
        assert isinstance(line, Traceline)
        try:
            next_line = trace[trace.index(line)+1]
        except:
            next_line = line
        try:
            prev_line = trace[trace.index(line)-1]
        except:
            prev_line = line
        if len(line.disasm) == 3:
            # add sth, 1
            if line.disasm[0].startswith('add') and line.disasm[2] == '1':
                line.disasm = ['inc', line.disasm[1]]
            # sub sth, 1
            elif line.disasm[0].startswith('sub') and line.disasm[2] == '1':
                line.disasm = ['dec', line.disasm[1]]
            # lea reg, [mem]
            elif line.disasm[0].startswith('lea') and get_reg_class(line.disasm[1]) is not None:
                # try:
                #     line.disasm = ['add', line.disasm[1], line.comment.split('=')[0]]
                #     assert line.disasm[2] != ''
                # except:
                #     line.disasm = ['mov', line.disasm[1], line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]]
                pass
        elif line.disasm_len == 2:
            if line.is_comparison and next_line.is_jmp:
                if trace[trace.index(next_line)+1].addr != int(next_line.disasm[1].split('_')[1], 16): # TODO
                    pass


    trace.standardization = True
    return trace


def optimization_unused_operand_folding(trace):
    """
    Remove unused operands. TODO
    :param trace:
    :return:
    """
    if not trace.constant_propagation:
        trace = optimization_const_propagation(trace)
    if not trace.stack_addr_propagation:
        trace = optimization_stack_addr_propagation(trace)
    kill_index = []
    for line in trace:
        assert isinstance(line, Traceline)
        if line.disasm[0].startswith('j'):
            kill_index.append(line)
        elif len(line.disasm) == 3:
            # if a value is computed and not used anymore we should remove all trace lines with it
            if line.is_mov:  # mov sth, sth
                # mov reg, sth and afterwards mov same_reg, sth without usage of said reg
                if line.is_op1_reg:
                    # value moved into reg and then overwritten
                    reg = line.disasm[1]
                    reg_class = get_reg_class(reg)
                    for other in trace[trace.index(line):]:
                        if len(other.disasm) == 3:
                            assert isinstance(other,Traceline)
                            if get_reg_class(other.disasm[1]) == get_reg_class(other.disasm[2]):  # mov eax, al
                                continue
                            elif other.disasm[1].__contains__(reg):  # mov eax, sth
                                kill_index.append(line)  # line is appended, line.DISASM[2] should be looked for and erased recursively during deletion
                                break
                            elif other.disasm[2].__contains__(reg) or get_reg_class(other.disasm[2]) == reg_class:  # register or part of it is used
                                break
                        if len(other.disasm) == 2:
                            if other.is_push and get_reg_class(other.disasm[1]) == reg_class:
                                break
                            elif other.is_pop and get_reg_class(other.disasm[1]) == reg_class:
                                kill_index.append(line)
                                break

                # mov [sth], sth
                elif line.disasm[1].startswith('[') and line.disasm[1].endswith(']'):
                    if get_reg_class(line.disasm[1][1:-1]) is not None:  # mov [reg], sth
                        pass
                    else: # mov [mem], sth -> constant propagation was already executed, so we assume things like [eax+edx] were already computed and changed to their corresponding value
                        mem_loc = line.disasm[1]
                        for other in trace[trace.index(line):]:
                            assert isinstance(other, Traceline)
                            if len(other.disasm) == 3:
                                if other.disasm[1].__contains__(mem_loc):
                                    kill_index.append(line)
                                    break
                                elif other.disasm[2].__contains__(mem_loc):
                                    break

    for line in kill_index:
        trace.pop(trace.index(line))
    trace.operation_folding = True
    return trace



def optimization_stack_addr_propagation(trace):
    """
    Add a comment to each line dereferencing an address. Executes constant propagation prior to execution if not already done.
    :param trace: unclustered trace
    :return: optimized trace
    """
    # first we build a pseudo stack
    pseudo_stack = {}
    if isinstance(trace, Trace) and not trace.constant_propagation:
        trace = optimization_const_propagation(trace)
    for line in trace:
        try:
            prev_line = trace[trace.index(line)-1]
        except:
            prev_line = line
        if len(line.disasm) == 3:
            # inst [mem] op
            if line.disasm[0].startswith('mov') and line.disasm[1].startswith('[') and line.disasm[1].endswith(']'):
                pseudo_stack[line.disasm[1]] = line.disasm[2]
            # inst op [mem]
            elif line.disasm[2].startswith('[') and line.disasm[2].endswith(']'):
                try:
                    # inst reg [mem]
                    if get_reg_class(line.disasm[1]) is not None and not line.disasm[0].startswith('lea'):
                        line.comment = '%s=%s' % (line.disasm[2], line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
                    elif get_reg_class(line.disasm[1]) is not None and line.disasm[0].startswith('lea'):
                        line.comment = '%s=%x' % (line.disasm[2], int(line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)], 16) -  # current register content minus
                                                  int(prev_line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)], 16))  # previous register content

                    else:
                        line.comment = '%s=%s' % (line.disasm[2], pseudo_stack[line.disasm[2]])

                except:
                    pass
            elif not line.disasm[0].startswith('mov') and line.disasm[1].startswith('[') and line.disasm[1].endswith(']'):
                try:
                    line.comment = '%s=%s' % (line.disasm[1], pseudo_stack[line.disasm[1]])
                except:
                    pass
            # inst reg [reg]
            elif line.disasm[2].__contains__('s:['):
                line.comment = '[%s]=%s' % (prev_line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)], line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
        elif len(line.disasm) == 2:
            # push
            if line.disasm[0].startswith('push'):
                if get_reg_class(line.disasm[1]) is not None:
                    pseudo_stack[prev_line.ctx[get_reg('rsp', trace.ctx_reg_size)]] = line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]
                else:
                    pseudo_stack[prev_line.ctx[get_reg('rsp', trace.ctx_reg_size)]] = line.disasm[1]
            # pop
            elif line.disasm[0].startswith('pop'):
                try:
                    pseudo_stack.pop(prev_line.ctx[get_reg('rsp', trace.ctx_reg_size)])
                except KeyError:
                    pass
        line.comment = line.comment.upper()
    trace.stack_addr_propagation = True

    return trace


def optimization_selective_register_folding(trace, reg_strings):
    """

    :param trace:
    :param reg_strings:
    :return:
    """
    ignored_regs = [get_reg_class(reg) for reg in reg_strings]
    kill_index = []
    for line in trace:
        if len(line.disasm) > 1:
            try:
                if line.is_op1_reg and get_reg_class(line.disasm[1]) in ignored_regs:
                    kill_index.append(line)
                elif line.is_op2_reg and get_reg_class(line.disasm[2]) in ignored_regs:
                    kill_index.append(line)
            except:
                pass

    for line in kill_index:
        trace.pop(trace.index(line))

    return trace


# list of all optimizations
optimizations = [optimization_const_propagation, optimization_stack_addr_propagation, optimization_standard_ops_folding, optimization_unused_operand_folding, optimization_peephole_folding]
# optimization names for human readability
optimization_names = ['Constant Propagation', 'Stack Address Propagation', 'Operation Standardisation (Folding)', 'Unused Operand Folding', 'Peephole (Folding)']


def optimize(trace):
    """
    run all available optimizations on the trace and present it
    :param trace:
    :return:
    """
    global optimizations
    for optimization in optimizations:
        trace = optimization(trace)
    return trace
