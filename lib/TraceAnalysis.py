# # coding=utf-8
# __author__ = 'Anatoli Kalysch'
#
import operator
from _collections import defaultdict
from copy import deepcopy

from TraceOptimizations import *
from dynamic.TraceRepresentation import Trace, Traceline
from idaapi import *
from idautils import *
from idc import *
from lib.VMRepresentation import get_vmr, VMContext


#############################################
### VISUALIZATION AND RESULT PRESENTATION ###
#############################################
def visualize_cli(cluster):
    """
    Visualize the cluster on the console or IDA Output window
    :param cluster: clustered trace or trace
    """
    print
    print
    for line in range(len(cluster)):
        if isinstance(cluster[line], Traceline):
            print '- single:' + cluster[line].to_str_line()
        elif isinstance(cluster[line], list):
            print
            print "+ cluster %s - %s:" % (hex(cluster[line][0].addr), hex(cluster[line][-1].addr))
            for num in range(len(cluster[line])):
                print '   ' + cluster[line][num].to_str_line()


# #######################################
# ### CLUSTERING AND RELATED FUNC     ###
# #######################################
def len_check(cluster):
    """
    length check for a clustered trace of trace lines
    :param cluster: clustered trace
    :return: length of the trace
    """
    l = 0
    for line in cluster:
        if isinstance(line, Traceline):
            l += 1
        elif isinstance(line, list):
            l += len(line)
    return l


def get_addr(op):
    """
    Get the address of a trace line of list of addresses for lists of trace lines recursively
    :param op:
    :return:
    """
    if isinstance(op, Traceline):
        # simple element
        return op.addr
    elif isinstance(op, list):
        # recursive in case list of lists
        return [get_addr(elem) for elem in op]


def address_count(trace):
    """
    Count the diffetent occurences of the addresses in the trace and return a sorted(highest->lowest) occurence list
    :param trace: execution trace of the binary
    :return: sorted list starting with the highest address count and ending with the lowest
    """
    trace = [line.addr for line in trace]
    analysis_result = {}
    for addr in trace:
        # for heuristic analysis the count of address
        count = trace.count(addr)
        if addr not in analysis_result.keys():
            analysis_result[addr] = count
    # sort the analysis result by most common addresses
    sorted_result = sorted(analysis_result.items(), key=operator.itemgetter(1))
    sorted_result.reverse()
    return sorted_result


def repetition_cluster_round(cluster_list):
    """
    One round of repetition cluster analysis.
    :param cluster_list: list of clusters
    :return: cluster list
    """
    vmr = get_vmr()
    assert isinstance(cluster_list, list)
    test_length = len_check(cluster_list)
    temp_cluster = [[cluster_list[cluster], cluster_list[cluster + 1]] for cluster in
                    range(0, len(cluster_list) - 1, 2)]

    # each tupel is tested for validity
    for cluster in temp_cluster:
        if cluster_list.count(cluster[0]) == cluster_list.count(cluster[1]):
            occurence = 0
            pop_indexes = []
            try:
                for j in range(len(cluster_list) - 1):
                    # if they are adjacent, they are labeled valid
                    if get_addr(cluster_list[j]) == get_addr(cluster[0]) and get_addr(cluster_list[j + 1]) == get_addr(
                            cluster[1]):
                        pop_indexes.append(j + 1)
                        occurence += 1
                if occurence > vmr.cluster_magic:  # if validity occured more than once we have a new cluster
                    pop_ctr = 0
                    for ind in pop_indexes:
                        addition = cluster_list.pop(ind - pop_ctr)
                        pop_ctr += 1
                        base = cluster_list[ind - pop_ctr]

                        if isinstance(base, Traceline):
                            if isinstance(addition, Traceline):
                                cluster_list[ind - pop_ctr] = [base, addition]
                            elif isinstance(addition, list):
                                cluster_list[ind - pop_ctr] = [base] + addition
                        elif isinstance(base, list):
                            if isinstance(addition, Traceline):
                                cluster_list[ind - pop_ctr].append(addition)
                            elif isinstance(addition, list):
                                cluster_list[ind - pop_ctr].extend(addition)
            except Exception, e:
                print e.message
                pass

    # clean up clusterlist
    for cluster in cluster_list:
        if isinstance(cluster, list):  # [Traceline, Traceline, ...]
            for j in cluster:
                if j.addr == BADADDR:
                    cluster.remove(j)
        elif not cluster or cluster.addr is BADADDR:
            cluster_list.remove(cluster)

    # if we are missing a trace element something went wrong
    assert test_length == len_check(cluster_list)
    return cluster_list


def create_bb_diff(bb, ctx_reg_size, prev_line_ctx):
    """
    Addr and thread id irrelevant; ctx shown as: before -> after; disasm (and comment) is chosen by heuristic.
    :param ctx_reg_size:
    :param prev_line_ctx:
    :param bb:
    return
    """
    first = bb[0]
    last = bb[-1]
    keys_f = prev_line_ctx.keys()
    keys_l = last.ctx.keys()
    context = {}
    disasm = []
    comment = []
    if keys_f == keys_l:
        for key in keys_f:
            if first.ctx[key] != last.ctx[key]:
                context[key] = first.ctx[key] + ' -> ' + last.ctx[key]
            else:
                context[key] = last.ctx[key]
    elif len(keys_l) > len(keys_f):
        for key in keys_f:
            if first.ctx[key] != last.ctx[key]:
                context[key] = first.ctx[key] + ' -> ' + last.ctx[key]
            else:
                context[key] = last.ctx[key]
        for key in list(set(keys_l) - set(keys_f)):
            context[key] = last.ctx[key]
    else:  # means keys_l < keys_f and if that happens sth went wrong. Should not be possible by normal execution.
        raise Exception('[*] Keys at the end of basic block %s-%s were LESS than at the beginning!' % (first.addr, last.addr))
    last_ctx = prev_line_ctx
    for line in bb:
        if line.comment is not None:
            comment.append(line.comment)
        if line.disasm[0].startswith('mov'):
            try:
                if bb[bb.index(line) + 1].disasm[0].startswith('mov') and get_reg_class(
                        bb[bb.index(line) + 1].disasm[1]) == get_reg_class(line.disasm[1]):
                    continue
            except:
                pass
            if line.disasm[1].startswith('[') and line.disasm[1].endswith(']'):
                comment.append(line.disasm[1] + '=' + line.disasm[2])
            elif get_reg_class(line.disasm[1]) is not None:
                continue
        elif line.disasm[0].startswith('j'):
            continue
        elif line.comment is not None and len(line.disasm) == 3 and line.disasm[1].startswith('['):
            if get_reg_class(line.disasm[2]) is not None:
                comment[-1] = comment[-1] + ' ' + line.disasm[0] + ' ' + last_ctx[get_reg(line.disasm[2], ctx_reg_size)]
            else:
                comment[-1] = comment[-1] + ' ' + line.disasm[0] + ' ' + line.disasm[2]
        elif line.comment is not None and len(line.disasm) == 3 and line.disasm[2].startswith('['):
            if get_reg_class(line.disasm[1]) is not None:
                comment[-1] = comment[-1] + ' ' + line.disasm[0] + ' ' + last_ctx[get_reg(line.disasm[1], ctx_reg_size)]
            else:
                comment[-1] = comment[-1] + ' ' + line.disasm[0] + ' ' + line.disasm[1]
        disasm.append(line.disasm)
        last_ctx = line.ctx

    result = Traceline(addr=last.addr, thread_id=last.thread_id, ctx=context, disasm=disasm, comment=comment)
    return result

def extract_stack_change(line, stack_changes):
    """
    Extracts the stack changes(=stack comments) from the line and inputs them into the stack_changes dict.
    :param line: a trace line
    :param stack_changes: the stack_changes dict
    :return: updated stack_changes
    """
    for comment in filter(None, line.comment):
        try:
            addr, value = ''.join(c for c in comment if c not in '[]').split('=')
            if stack_changes[addr] != 0 and not stack_changes[addr].endswith(value):
                stack_changes[addr] = stack_changes[addr] + '->' + value
            else:
                stack_changes[addr] = value
        except Exception, e:
            print e.message
            print e.args

    return line, stack_changes


def create_cluster_gist(cluster, ctx_reg_size, prev_line_ctx, stack_changes):
    """
    Function takes a cluster, subdivides it into basic blocs (if any). For each bb a representative traceline is created which consists of relevant
    instructions, relevant stack changes and shows the difference in the registers between fist ans last bb line.
    :param cluster: list of Tracelines
    :return: appeared stack_changes
    """
    bbs = []
    bb = []
    # subdivide the clusters by basic blocks
    for line in cluster:
        if is_basic_block_end(line.addr):
            bb.append(line)
            bbs.append(bb)
            bb = []
        else:
            bb.append(line)

    for bb in bbs:
        bb_gist = create_bb_diff(bb, ctx_reg_size, prev_line_ctx)
        bb_gist, stack_changes = extract_stack_change(bb_gist, stack_changes)
        prev_line_ctx = bb[-1].ctx

    return stack_changes


def repetition_clustering(trace, **kwargs):
    """
    Cluster the trace into groups of repeating instructions(=clusters) and non-repeating instructions(=singles)

    :param trace: instruction trace
    :param kwargs: rounds=clustering_rounds
    :return: list where an element is either another list(=cluster of addrs) or an int (=single addr)
    """
    rounds = kwargs.get('rounds', None)
    if trace is None:
        raise Exception("[*] Empty trace, nothing to cluster!")

    clusters_final = trace
    if rounds:
        for j in range(int(rounds)):
            clusters_final = repetition_cluster_round(clusters_final)
    else:  # assuming greedy, since it produces best results im most cases
        pre = 1
        post = 0
        while pre != post:
            pre = len(clusters_final)
            clusters_final = repetition_cluster_round(clusters_final)
            post = len(clusters_final)


    return clusters_final


def cluster_removal(trace, **kwargs):
    # remove the *threshold* most common basic blocks -> often the vm handler routine to get next vm_instruction
    """
    Remove certain amount of clusters. Clusters to be removed are determined dynamically by the frequency of their occurrence.
    :param trace: instruction trace
    :param kwargs: threshold='how many clusters to remove'
    :return: clustered trace without *threshold* clusters
    """
    threshold = kwargs.get('threshold', 1)

    kill_addrs = []
    addr_list = address_count(trace)
    # how often are *threshold* basic blocks repeated?

    temp = set()
    for tupel in addr_list:
        temp.add(tupel[1])
        if len(temp) >= threshold:
            break
    # fill the kill index with to remove addresses
    for tupel in addr_list:
        if tupel[1] in temp:
            kill_addrs.append(tupel[0])

    kill_index = [line for line in trace if line.addr in kill_addrs]
    for line in kill_index:
        trace.pop(trace.index(line))

    return trace

#####################################
### VM ANALYSIS FUNCTIONS         ###
#####################################
def find_vm_addr(trace):
    """
    Find the virtual machine addr
    :param trace: instruction trace
    :return: virtual function start addr
    """
    push_dict = defaultdict(lambda: 0)
    vm_func_dict = defaultdict(lambda: 0)
    # try to find the vm Segment via series of push commands, which identify the vm_addr also
    for line in trace:
        try:
            if line.disasm[0] == 'push':
                push_dict[GetFunctionAttr(line.addr, FUNCATTR_START)] += 1
        except:
            pass

    vm_func = max(push_dict, key=push_dict.get)
    vm_seg_start = SegStart(vm_func)
    vm_seg_end = SegEnd(vm_func)
    # test wheather the vm_func is the biggest func in the Segment
    vm_funcs = Functions(vm_seg_start, vm_seg_end)
    for f in vm_funcs:
        vm_func_dict[f] = GetFunctionAttr(f, FUNCATTR_END) - GetFunctionAttr(f, FUNCATTR_START)
    if max(vm_func_dict, key=vm_func_dict.get) != vm_func:
        return AskAddr(vm_func,
                "Found two possible addresses for the VM function start address: %s and %s. Choose one!" %
                (vm_func, max(vm_func_dict, key=vm_func_dict.get)))
    else:
        return vm_func


def extract_vm_segment(trace):
    """
    Identify the VM Segment, Extract only the VM part of the trace and return the cleaned trace and start/end addr.
    :param trace: instruction trace
    :return: cleaned trace, start addr of vm segment, end addr of vm segment, vm_addr_candidate
    """
    vm_seg_start = None
    vm_seg_end = None
    # try to find the vm Segment via name -> easiest case but also easy to foil
    for addr in Segments():
        if SegName(addr).startswith('.vmp'):
            vm_seg_start = SegStart(addr)
            vm_seg_end = SegEnd(addr)
            break

    # if that fails, find the vm_function and use its segment
    if not vm_seg_start or not vm_seg_end:
        vm_addr = find_vm_addr(trace)

        vm_seg_start = SegStart(vm_addr)
        vm_seg_end = SegEnd(vm_addr)
    return [line for line in trace if vm_seg_start < line.addr and vm_seg_end > line.addr], vm_seg_start, vm_seg_end


def dynamic_vm_values(trace, code_start=BADADDR, code_end=BADADDR, silent=False):
    """
    Find the virtual machine context necessary for an automated static analysis.
    code_start = the bytecode start -> often the param for vm_func and usually starts right after vm_func
    code_end = the bytecode end -> bytecode usually a big chunk, so if we identify several  x86/x64 inst in a row we reached the end
    base_addr = startaddr of the jmp table -> most often used offset in the vm_trace
    vm_addr = startaddr of the vm function -> biggest function in .vmp segment,
    :param trace: instruction trace
    :return: vm_ctx -> [code_start, code_end, base_addr, vm_func_addr, vm_funcs]
    """
    base_addr = defaultdict(lambda: 0)
    vm_addr = find_vm_addr(deepcopy(trace))
    trace, vm_seg_start, vm_seg_end = extract_vm_segment(trace)

    code_addrs = []

    # try finding code_start
    if code_start == BADADDR:
        code_start = GetFunctionAttr(vm_addr, FUNCATTR_END)#NextHead(GetFunctionAttr(vm_addr, FUNCATTR_END), vm_seg_end)
        code_start = NextHead(code_start, BADADDR)
        while isCode(code_start):
            code_start = NextHead(code_start, BADADDR)

    for line in trace:
        # construct base addr dict of offsets -> jmp table should be the one most used
        if len(line.disasm) == 2:
            try:
                offset = re.findall(r'.*:off_([0123456789abcdefABCDEF]*)\[.*\]', line.disasm[1])[0]
                base_addr[offset] += 1
            except:
                pass
        # code_start additional search of vm_func params
        if line.addr == vm_addr:
            for l in trace[:trace.index(line)]:
                if l.disasm[0] == 'push':
                    try:
                        arg = re.findall(r'.*_([0123456789ABCDEFabcdef]*)', l.disasm[1])
                        if len(arg) == 1:
                            code_addrs.append(int(arg[0], 16))
                    except Exception, e:
                        print e.message

    # finalize base_addr
    max_addr = int(max(base_addr, key=base_addr.get), 16)  # now we have the base_addr used for offset computation - this will probably be the top of the table but to be sure we need to take its relative position into account
    base_addr = max_addr
    while GetMnem(PrevHead(base_addr)) == '':
        base_addr = PrevHead(base_addr)


    # finalize code_start
    if not silent:
        if code_start not in code_addrs:
            code_start = AskAddr(code_start, "Start of bytecode mismatch! Found %x but parameter for vm seem to be %s" % (code_start, [hex(c) for c in code_addrs]))

    # code_end -> follow code_start until data becomes code again
    if code_end == BADADDR:
        code_end = vm_seg_end
        # while code_end < vm_seg_end:
        #     code_end = NextHead(code_end, vm_seg_end)
        #     if isCode(code_end):
        #         break
    vm_ctx = VMContext()
    vm_ctx.code_start = code_start
    vm_ctx.code_end = code_end
    vm_ctx.base_addr = base_addr
    vm_ctx.vm_addr = vm_addr

    print code_start, code_end, base_addr, vm_addr

    return vm_ctx


def find_virtual_regs(trace, manual=False, update=None):
    """
    Maps the virtual registers on the stack to the actual registers after the vm exit.
    :param trace: instruction trace
    :return: virtual registers dict which maps the real regs onto virtual ones via stack addresses
    """
    vmr = get_vmr()
    assert isinstance(trace, Trace)
    virt_regs = defaultdict(lambda: False)
    # trace, vm_seg_start, vm_seg_end = extract_vm_segment(trace)

    while trace:
        try:
            elem = trace.pop(len(trace) - 1)
            if len(elem.disasm) > 0 and elem.disasm[0] == 'pop':
                opnd = elem.disasm[1]
                if get_reg_class(opnd) is None:  # if not a register it is a mem_loc
                    pass
                elif virt_regs[opnd]:
                    pass
                else:
                    # the context always shows the registers after the execution, so we nee the SP from the instruction before
                    stack_addr = trace[len(trace) - 1].ctx[get_reg('rsp', trace.ctx_reg_size)]
                    virt_regs[opnd] = stack_addr
        except:
            pass

    if update is not None:
        update.pbar_update(60)

    vmr.vm_stack_reg_mapping = virt_regs
    if manual:
        print ''.join('%s:%s\n' % (c, virt_regs[c]) for c in virt_regs.keys())
    return virt_regs


def find_ops_callconv(trace, vmp_seg_start, vmp_seg_end):
    """
    find params on stack before function call
    :param vmp_seg_start: start of vm segment
    :param vmp_seg_end: end of vm segment
    :param trace: instruciton trace
    :return: set of operands
    """
    # call_depth is the number of call instructions the algo goes through  to analyze the passed args -> useful if VM consists of more than one function (most have have at least 2)
    call_depth = 2
    ops = []
    calls = 0
    for line in trace:
        # we search backwards for call inst and then further for stack push or mov to stack addr
        if vmp_seg_start <= line.addr <= vmp_seg_end:
            for i in range(trace.index(line) - 1, 0, -1):
                if trace[i].disasm[0].startswith('call'):
                    for j in range(i):
                        line = trace[i - j]
                        if line.disasm[0].startswith('call') and not vmp_seg_start <= line.addr <= vmp_seg_end:
                            calls += 1
                            if calls >= call_depth:
                                break
                        # push reg/const
                        elif line.disasm[0].startswith('push'):
                            ops.append(line.disasm[1])
                        # mov instructions; only xsp related
                        elif line.disasm[0].startswith('mov'):
                            try:
                                op1 = re.findall(r'.*\[(.*)\].*', line.disasm[1])[0]
                                op2 = line.disasm[2]
                                try:  # mov [xsp +/-/* reg/const], reg/const
                                    expr = re.findall(r'.*([\+\-\*\/]).*', line.disasm[1])[0]  # find math expr + or - or * or /
                                    elem = op1.split(expr)

                                    for e in elem:
                                        if get_reg_class(e) is 7:  # 7 is the esp class
                                            if get_reg_class(op2) is not None:  # mov [*xsp*], reg
                                                ops.append(line.ctx[get_reg(op2, trace.ctx_reg_size)])
                                            else:  # mov [*xsp*], const
                                                ops.append(line.disasm[2])
                                            break
                                except:
                                    # mov [xsp]/[mem], reg/const
                                    if get_reg_class(op1) is 7 or get_reg_class(op1) is None:  # 7 is the esp class
                                        if get_reg_class(op2) is not None:  # mov [xsp], reg
                                            ops.append(line.ctx[get_reg(op2, trace.ctx_reg_size)])
                                        else:  # mov [xsp], const
                                            ops.append(line.disasm[2])
                            except:
                                # if no [.*] was found, it means the mov instructions were not onto the stack
                                pass

    return ops


def find_input(trace, manual=False, update=None):
    """
    Find input operands to the vm_function.
    :param trace: instruciton trace
    :param manual: console output z/n
    :return: a set of operands to the vm_function
    """
    vmr = get_vmr()
    if vmr.func_args:
        func = GetFunctionName(find_vm_addr(deepcopy(trace)))
        func_args = vmr.func_args[func]
    ops = set()
    if update is not None:
        update.pbar_update(20)
    ex_trace, vmp_seg_start, vmp_seg_end = extract_vm_segment(deepcopy(trace))  # use deepcopy trace, since we need the full one  for find_ops_callconv
    if update is not None:
        update.pbar_update(20)
    for line in ex_trace:
        try:
            # case inst reg, ss:[reg]
            op = line.disasm[2]
            # following is ida only
            if op.startswith('ss:'):
                # get the reg value from ctx
                op = line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)]
                ops.add(op.upper())
        except:
            pass
    try:
        # if we find the .vmp Segment addr or vm-function addr we should check the stack
        for op in find_ops_callconv(trace, vmp_seg_start, vmp_seg_end):
            ops.add(op.upper())  # set will eliminate double entries
        if update is not None:
            update.pbar_update(30)
        for op in func_args:
            ops.add(op.upper())
    except:
        pass

    if update is not None:
        update.pbar_update(10)
    if manual:
        print 'operands: %s' % ''.join('%s | ' % op for op in ops)
    return ops

def find_output(trace, manual=False, update=None):
    """
    Find output operands to the vm_function.
    :param trace: instruction trace
    :param manual: console output y/n
    :return: set of output operands
    """
    if update is not None:
        update.pbar_update(20)
    ex_trace, vmp_seg_start, vmp_seg_end = extract_vm_segment(deepcopy(trace))
    ex_trace.reverse()
    if update is not None:
        update.pbar_update(20)
    pop_lines = []
    lastline = ''
    ctx = {}
    for line in ex_trace:
        if line.disasm[0].startswith('ret'):
            ctx = line.ctx
            lastline = line
            break
        elif line.disasm[0].startswith('pop'):
            ctx = line.ctx
            lastline = line
            break
    if update is not None:
        update.pbar_update(40)
    if manual:
        print ''.join('%s:%s\n' % (c, ctx[c]) for c in ctx.keys() if get_reg_class(c) is not None)
    return set([ctx[get_reg(reg, trace.ctx_reg_size)].upper() for reg in ctx if get_reg_class(reg) is not None])


def follow_virt_reg(trace, **kwargs):
    """
    Follows the virtual registers and extracts the relevant trace lines to clarify how the final result in a virtual register came to be and what values(=recursively) it consists of.
    :param trace: instruction trace
    :param virt_reg_addr: the stack addr of the virtual register
    :param real_reg_name: reg string
    :return: trace consisting of relevant tracelines for the virtual register
    """
    update = kwargs.get('update', None)
    manual = kwargs.get('manual', False)

    if manual:
        real_reg_name = AskStr('eax', 'Which register do you want followed?')
        if real_reg_name is None:
            real_reg_name = get_reg('rax', trace.ctx_reg_size)
        else:
            real_reg_name = get_reg(real_reg_name, trace.ctx_reg_size)
    else:
        real_reg_name = kwargs.get('real_reg_name', get_reg('rax', trace.ctx_reg_size))
    virt_reg_addr = kwargs.get('virt_reg_addr', None)

    if virt_reg_addr is None:
        vr = find_virtual_regs(deepcopy(trace))
        virt_reg_addr = vr[real_reg_name]

    if update is not None:
        update.pbar_update(30)
    backtrace = Trace()
    watch_addrs = set()
    reg_vals = set()

    trace = optimization_const_propagation(trace)

    trace = optimization_stack_addr_propagation(trace)

    if update is not None:
        update.pbar_update(10)
    # reversing the trace makes the backward tracersal easier
    trace.reverse()

    # get reg value at pop
    reg = get_reg(real_reg_name, trace.ctx_reg_size)
    for line in trace:
        if len(line.disasm) == 2:
            if line.disasm[0] == 'pop' and get_reg_class(line.disasm[1]) == get_reg_class(reg):
                reg_vals.add(line.ctx[reg])
                break


    watch_addrs.add(virt_reg_addr)

    for line in trace:
        assert isinstance(line,Traceline)
        if line.is_jmp:
            continue
        try:
            # +1 because trace is reversed to get to prev element
            prev = trace[trace.index(line)+1]
            for val in reg_vals.copy():
                if val in line.ctx.values() and val not in prev.ctx.values():
                    backtrace.append(line)
                    # if val suddenly appears in the ctx there should be 2 possibilities:
                    # 1. it was moved from mem, so it was on the stack -> append stack addres to be watched out for
                    if line.is_mov and line.is_op2_mem:
                        watch_addrs.add(''.join(c for c in line.disasm[2] if c not in '[]'))
                        #reg_vals.remove(val)
                    # 2. it was computed -> if regs played a role in the computation add them to values to watch out for
                    elif not line.is_mov:
                        if line.disasm_len > 2:
                            if line.is_op1_reg:
                                reg_vals.add(line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
                            if line.is_op1_mem:
                                watch_addrs.add(''.join(c for c in line.disasm[1] if c not in '[]'))
                            if line.is_op2_reg:  # not necessarily the case for lea
                                reg_vals.add(line.ctx[get_reg(line.disasm[2], trace.ctx_reg_size)])
                            if line.is_op2_mem:
                                watch_addrs.add(''.join(c for c in line.disasm[2] if c not in '[]'))
                        elif line.disasm_len == 2:
                            if line.is_op1_reg:
                                reg_vals.add(line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
                                if line.ctx[get_reg('eax', trace.ctx_reg_size)] != prev.ctx[get_reg('eax', trace.ctx_reg_size)]:
                                    reg_vals.add(line.ctx[get_reg('eax', trace.ctx_reg_size)])
                                if line.disasm[0].startswith('not'):
                                    reg_vals.add(line.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
                                    reg_vals.add(prev.ctx[get_reg(line.disasm[1], trace.ctx_reg_size)])
                                    backtrace.append(prev)
                                    backtrace.append(trace[trace.index(line)-1])
                                    try:
                                        reg_vals.add(prev.ctx[get_reg(prev.disasm[1], trace.ctx_reg_size)])
                                        reg_vals.add(trace[trace.index(line)-1].ctx[get_reg(prev.disasm[1], trace.ctx_reg_size)])
                                    except:
                                        pass


        except Exception, e:
            pass
            #print 'reg_vals\n',line, e.message
        if watch_addrs:
            for addr in watch_addrs.copy():
                try:
                    if line.disasm[1].__contains__(addr):
                        backtrace.append(line)

                        reg_vals.add(line.disasm[2])
                        r = line.ctx.keys()[line.ctx.values().index(line.disasm[2])]
                        for i in range(len(trace)):
                            temp = trace[trace.index(line)+i]
                            if len(temp.disasm) == 3:
                                if temp.disasm[1][-2:] == r[-2:]:
                                    if get_reg_class(r[-2:]) is not None:
                                            watch_addrs.add(temp.disasm[2][1:-1])
                                            break

                        if line.is_mov:
                            watch_addrs.remove(addr)
                except Exception, e:
                    #print 'watch_addr\n',line, e.message
                    pass

    if update is not None:
        update.pbar_update(40)
    # reverse the reversed bt
    backtrace.reverse()
    if manual:
        print
        for line in backtrace:
            print line.to_str_line()

    return backtrace