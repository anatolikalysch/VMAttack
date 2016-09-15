#!/usr/bin/env python

"""
@author: Tobias
"""


import lib.PseudoInstruction as PI
from lib import StartVal as SV
from lib.Register import (get_reg_class, get_reg_by_size)


def remove_dropped(ps_lst):
    """
    @brief Removes every item of ps_lst which is marked to drop
    @param ps_lst List of PseudoInstructions
    @return List of PseudoInstructions
    """
    ret = []
    for item in ps_lst:
        if not item.drop:
            ret.append(item)
        else:
            del item
    return ret


def find_last_inst(pp_lst, start_pos, op):
    """
    @brief Finds last instruction which has an operand that is equal to op
    @param pp_lst List of PseudoInstructions push/pop represtentation
    @param start_pos Startindex for searching
    @param op Operand that must be found
    @return Found index
    """
    pos = start_pos
    while pos != 0:
        inst = pp_lst[pos]
        if inst.inst_type == PI.POP_T and inst.op_lst[0] == op:
            #print 'pop', op
            return pos
        if inst.inst_class == PI.ASSIGNEMENT_T and op in inst.op_lst:
            #print 'assignement', op
            return pos
        pos -= 1
    return None


def start_rec(pp_lst, jmp_pos):
    """
    @brief Starts recursiv search for jmp addresses
    @param pp_lst List of PseudoInstructions push/pop represtentation
    @param jmp_pos Index of jump instruction
    @return List of Tuple: (position of jump addr, address of jump instruction)
    """
    jmp_inst = pp_lst[jmp_pos]
    if jmp_inst.list_len == 0:
        print 'could not find jmp address'
        return []
    jmp_op = jmp_inst.op_lst[0]
    pos_lst = rec_find_addr(pp_lst, jmp_pos, jmp_op, 20)
    ret_lst = []
    for x in pos_lst:
        ret_lst.append((x, pp_lst[jmp_pos].addr))
    return ret_lst


def rec_find_addr(pp_lst, pos, op, max_rec_depth):
    """
    @brief Recursiv search for finding jmp addresses
    @param pp_lst List of PseudoInstructions push/pop represtentation
    @param pos Index of jump instruction
    @param op Operand of jump instruction
    @param max_rec_depth Maximal recursion depth
    @return List positions which are used to calc jump address
    """
    if max_rec_depth == 0:
        return []
    if(op.type == PI.IMMEDIATE_T or
       (op.type == PI.REGISTER_T and
        get_reg_class(op.register) == get_reg_class('ebp'))):
        return [pos]
    inst_pos = find_last_inst(pp_lst, pos - 1, op)
    if inst_pos == None or inst_pos == 0:
        return []
    curr_inst = pp_lst[inst_pos]
    if curr_inst.inst_type == PI.POP_T:
        push_pos = last_rel_push(pp_lst, inst_pos - 1)
        if push_pos == None:
            return []
        new_op = pp_lst[push_pos].op_lst[0]
        new_pos = push_pos
        return [] + rec_find_addr(pp_lst, new_pos, new_op, max_rec_depth-1)
    elif (curr_inst.inst_class == PI.ASSIGNEMENT_T and
            curr_inst.list_len == 2):
        new_op = pp_lst[inst_pos].op_lst[1]
        new_pos = inst_pos
        return [] + rec_find_addr(pp_lst, new_pos, new_op, max_rec_depth-1)
    elif (curr_inst.inst_class == PI.ASSIGNEMENT_T and
            curr_inst.list_len >= 2):
        new_pos = inst_pos
        ret_lst = []
        for new_op in curr_inst.op_lst[1:]:
            ret_lst += rec_find_addr(pp_lst, new_pos , new_op, max_rec_depth-1)
        return ret_lst
    else:
        return []


def get_jmp_addresses(pp_lst, code_eaddr):
    """
    @brief Determines the jump addresses of all jump instructions
    @param pp_lst List of PseudoInstructions push/pop represtentation
    @param code_eaddr End address of obfuscated code
    @return List of Tuples: (jump addres, address of jump instruction)
    """
    jp_lst = []
    for pos, inst in enumerate(pp_lst):
        if inst.inst_type == PI.JMP_T:
            jp_lst.append(pos)
    poss_adr_pos = []
    for jpos in jp_lst:
        poss_adr_pos += start_rec(pp_lst, jpos)
    if len(poss_adr_pos) == 0:
        print 'could not find addresses'
        return []
    addrs = []
    for pos, jaddr in poss_adr_pos:
        inst = pp_lst[pos]
        if inst.op_lst[0].type == PI.REGISTER_T:
            push_pos = pos - 1
            count = 0
            tmp_addrs = []
            while(pp_lst[push_pos].inst_type == PI.PUSH_T and # TODO this seems kind of unsave
                  pp_lst[push_pos].op_lst[0].type == PI.IMMEDIATE_T and
                  push_pos != 0):
                tmp_addrs.append((pp_lst[push_pos].op_lst[0].val, jaddr))
                count += 1
                push_pos -= 1
            if count < 2:
                tmp_addrs = []
            addrs += tmp_addrs
        elif inst.op_lst[0].type == PI.IMMEDIATE_T:
            value = inst.op_lst[0].val
            if value > 0x400000 and value < 0x600000: #TODO
                addrs.append((value, jaddr))
    for pos_jmp in jp_lst:
        jmp_inst = pp_lst[pos_jmp]
        comment = 'jumps to: '
        found_addr = False
        for (addr, jaddr) in addrs:
            if jaddr == jmp_inst.addr:
                comment += '{0:#x}, '.format(addr)
                found_addr = True
        if found_addr:
            comment = comment[:len(comment)-2]
        else:
            comment += 'not found'
        jmp_inst.comment = comment
    return addrs


def find_basic_blocks(pp_lst, start_addr, jmp_addrs):
    """
    @brief Determines which parts are basic blocks
    @param pp_lst List of PseudoInstructions push/pop represtentation
    @param start_addr Start address of obfuscated function
    @param jmp_addrs List of Tuples:(jump address, address of jump instruction)
    @return List of Tuples:(basic block start address, basic block end address)
    """
    leader_lst = []
    leader_lst.append(start_addr)
    for pos, inst in enumerate(pp_lst):
        if inst.inst_type == PI.JMP_T or inst.inst_type == PI.RET_T:
            if pos < len(pp_lst) - 1:
                leader_lst.append(pp_lst[pos+1].addr)
                #leader_lst.append(inst.addr + 1) # i think this is better
            else: # code end
                leader_lst.append(inst.addr + 1)
    for addr in jmp_addrs:
        leader_lst.append(addr[0])
    basic_blocks = []
    rel_addrs = sorted(list(set(leader_lst)))
    for pos, x, in enumerate(rel_addrs):
        if (pos < len(rel_addrs) - 1):
            end_addr = rel_addrs[pos+1]
            basic_blocks.append((x, end_addr))
    del leader_lst
    del rel_addrs
    #for x, y in basic_blocks:
    #    print 'BasicBlock From: {0:#x}'.format(x), ' To: {0:#x}'.format(y)
    if basic_blocks == []:
        return None
    return basic_blocks


# still not sure if this is right for evry possibility
def last_rel_push(ps_lst, pos):
    """
    @brief Detrmines the corresponding 'push' to a 'pop' at position pos
    @param ps_lst List of PseudoInstructions
    @param pos Positon of 'pop' instruction
    return Position of 'push' instruction
    """
    counter = 0
    while pos >= 0:
        if(ps_lst[pos].inst_type == PI.POP_T):
            counter += ps_lst[pos].size
        elif(ps_lst[pos].inst_type == PI.PUSH_T):
            if counter == 0:
                #return ps_lst[pos]
                return pos
            else:
                counter -= ps_lst[pos].size
        pos -= 1
    else: #no break
        return None



#     optimize_functions      #


def optimize(pseudo_inst_lst, has_loc):
    """
    @brief Starts all optimization functions;
    optimizes the output
    @param pseud_inst_lst List of PseudoInstructions
    @param has_loc Indicates if there are locals in this function
    @return List of optimized PseudoInstructions
    """
    replace_scratch_variables(pseudo_inst_lst)
    pseudo_inst_lst = replace_push_ebp(pseudo_inst_lst, has_loc)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = replace_pop_push(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    reduce_assignements(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = convert_read_array(pseudo_inst_lst)
    reduce_assignements(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = change_nor_to_not(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    #return_push_ebp(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    reduce_ret(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    #scan_for_arguments(pseudo_inst_lst)
    add_comments(pseudo_inst_lst)
    count_left_push(pseudo_inst_lst)
    count_left_pop(pseudo_inst_lst)
    delete_overwrote_st(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    ##TODO remove unused just for whole function
    ##remove_unused(pseudo_inst_lst)
    ##pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    return remove_dropped(pseudo_inst_lst)


#unitll now this seems to be te best possibility
#think about saving the offsets of edi in Variable_T
def replace_scratch_variables(ps_lst):
    """
    @brief Replaces scratch variables with temporal variables
    @param ps_lst List of PseudoInstructions
    """
    for pos, item in enumerate(ps_lst):
        if item.list_len <= 0:
            continue
        if item.inst_type != PI.POP_T or item.op_lst[0].type != PI.SVARIABLE_T:
            continue
        st_operand = item.op_lst[0]
        var_operand = PI.VariableOperand(PI.VARIABLE_T, st_operand.size)
        if replace_st_push(ps_lst, pos, st_operand, var_operand):
            item.op_lst[0] = var_operand


def replace_st_push(ps_lst, pos, to_replace, replace):
    """
    @brief Replaces scratch operand to_replace with operand replace
    in every 'push' instruction until next 'pop' instruction
    with scratch operand to_replace
    @param ps_lst List of PseudoInstructions
    @param pos Starting postion for replacement
    @param to_replace Scratch operand that will be replaced
    @param replace Varibale operand which replaces to_replace
    @return True if a replacement took place, False otherwise
    """
    lst_len = len(ps_lst)
    is_replace = False
    counter = pos + 1
    while counter < lst_len:
        curr_inst = ps_lst[counter]
        if curr_inst.list_len <= 0:
            counter += 1
            continue
        if(curr_inst.inst_type == PI.POP_T and
           curr_inst.op_lst[0].name == to_replace.name):
            return is_replace
        if(curr_inst.inst_type == PI.PUSH_T and
           curr_inst.op_lst[0].name == to_replace.name):
            ps_lst[counter].op_lst[0] = replace
            is_replace = True
        counter += 1
    return is_replace


def search_last_inst(count, ps_lst, last_pos, instruction_flag):
    """
    @brief Determines the last count instructions
    with the flag instruction_flag
    @param count Number of last instructions that should be found
    @param ps_lst List of PseudoInstructions
    @param last_pos Last position to search
    @param instruction_flag Flag that defines a instruction
    @return List of indices or None
    """
    i = 0
    ret = []
    while i < count:
        ret.append(-1)
        i += 1
    actual_pos = 0
    for pos, item in enumerate(ps_lst):
        if(pos >= last_pos):
            break
        if(item.inst_type == instruction_flag and not item.drop):
            ret[actual_pos % count] = pos
            actual_pos += 1
    if (ret.count(-1) != 0):
        return None
    else:
        return ret


def size_to_str(size):
    """
    @brief Determines a string representation for a given size
    """
    lookup = {1:'b', 2:'w', 4:'d', 8:'q'}
    try:
        return lookup[size]
    except:
        return ''


def is_mov_ebp(ps_lst, start, end):
    """
    @brief Determines if a mov ebp instruction is between
    start and end
    @param ps_lst List of PseudoInstructions
    @param start Startposition in ps_lst for search
    @param end Endposition in ps_lst for search
    @return True if mov ebp instruction is found, False otherwise
    """
    currpos = start
    while currpos <= end:
        inst = ps_lst[currpos]
        if inst.inst_type == PI.MOV_EBP_T:
            return True
        else:
            currpos += 1
    return False


def is_undef_inst(ps_lst, start, end):
    """
    @brief Determines if a undefined instruction is between
    start and end
    @param ps_lst List of PseudoInstructions
    @param start Startposition in ps_lst for search
    @param end Endposition in ps_lst for search
    @return True if undefined instruction is found, False otherwise
    """
    currpos = start
    while currpos <= end:
        inst = ps_lst[currpos]
        if inst.inst_type == PI.UNDEF_T:
            return True
        else:
            currpos += 1
    return False


def replace_pop_push(ps_lst):
    """
    @brief Replaces push- pop pairs with assignements
    @param ps_lst List of PseudoInstructions
    @return List of PseudoInstructions
    """
    ret = []
    rest_size = None
    for pos, item in enumerate(ps_lst):
        if item.inst_type == PI.POP_T and not item.drop:
            pos_lst = search_last_inst(1, ps_lst, pos, PI.PUSH_T)
            if pos_lst == None:
                ret.append(item)
                continue
            push_pos = pos_lst[0]
            #the reduction of push and pop must not take place
            #if there is a change of the stackpointer or a
            #undefined instruction between the push and pop instruction
            if (is_mov_ebp(ps_lst, push_pos, pos) or
                is_undef_inst(ps_lst, push_pos, pos)):
                ret.append(item)
                continue
            push_inst = ps_lst[push_pos]
            if item.size == push_inst.size:
                item.drop = True
                push_inst.drop = True
                op = ps_lst[push_pos].op_lst[0]
                assign_op = item.op_lst[0]
                ret.append(
                    PI.PseudoInstruction('', item.addr, [assign_op, op], -1,
                                        PI.NOTHING_T, PI.ASSIGNEMENT_T)
                    )
            # popsize lower push size
            elif item.size < push_inst.size:
                #dont know if this is bad style but it works
                if rest_size == None:
                    counter = 0
                    rest_size = push_inst.size
                rest_size = rest_size - item.size
                push_op = ps_lst[push_pos].op_lst[0]
                suffix = '_PART' + str(counter) + '_' + size_to_str(item.size)
                op = PI.PseudoOperand(push_op.type,
                                      push_op.name + suffix, push_op.size)
                assign_op = item.op_lst[0]
                ret.append(
                    PI.PseudoInstruction('', item.addr, [assign_op, op],
                                         -1, PI.NOTHING_T, PI.ASSIGNEMENT_T)
                    )
                counter += 1
                item.drop = True
                if rest_size == 0:
                    rest_size = None
                    push_inst.drop = True
            # popsize greater push size
            elif item.size > push_inst.size:
                needed_pushes = item.size / push_inst.size
                pos_lst = search_last_inst(needed_pushes, ps_lst, pos, PI.PUSH_T)
                if pos_lst == None:
                    continue
                for i, p_pos in enumerate(reversed(sorted(pos_lst))):
                    #op = ps_lst[push_pos].op_lst[0]
                    push_op = ps_lst[p_pos].op_lst[0]
                    suffix = '_PART' + str(i) + '_' + size_to_str(push_inst.size)
                    assign_op = PI.PseudoOperand('', item.op_lst[0].name + suffix, item.op_lst[0].size,)
                    ret.append(
                        PI.PseudoInstruction('', item.addr, [assign_op, push_op],
                                             -1, PI.NOTHING_T, PI.ASSIGNEMENT_T)
                        )
                    ps_lst[p_pos].drop = True
                item.drop = True
            else:
                ret.append(item)
        else:
            ret.append(item)
    return ret

# TODO verbessern
def replace_temporals(ps_lst, pos, to_replace, replace):
    """
    @brief Replaces temporal operand to_replace with operand replace
    @param ps_lst List of PseudoInstructions
    @param pos Starting postion for replacement
    @param to_replace Scratch operand that will be replaced
    @param replace Varibale operand which replaces to_replace
    @return True if a replacement took place, False otherwise
    """
    lst_len = len(ps_lst)
    counter = pos + 1
    found = False
    while counter < lst_len:
        for op_pos, op in enumerate(ps_lst[counter].op_lst):
            if op.type == PI.ARRAY_T:
                for a_pos, a_op in enumerate(op.op_val):
                    if a_op.name == to_replace.name:
                        ps_lst[counter].op_lst[op_pos].op_val[a_pos] = replace
                        found = True
            if op.name == to_replace.name: # maybe improve this comparion
                #idee: falls der Variablen etwas neues zugewiesen
                #wird bevor(op_pos == 0) beende das ersetzen
                #die letze instruction kann geloescht werden
                if(op_pos == 0 and ps_lst[counter].inst_class == PI.ASSIGNEMENT_T and
                   ps_lst[counter].inst_type == PI.NOTHING_T): # TODO improve
                    return False # return True
                if(op.type == PI.POINTER_T):
                    ps_lst[counter].op_lst[op_pos] = PI.PseudoOperand(
                            PI.POINTER_T, replace.name,
                            replace.size, counter)
                else:
                    ps_lst[counter].op_lst[op_pos] = replace
                found = True
        counter += 1
    return found
        


def reduce_assignements(ps_lst):
    """
    @brief Reduces assignements e.g.:
    converts 'T2 = T1' and 'T3 = T2' to 'T3 = T1'
    @param ps_lst List of PseudoInstructions
    """
    for pos, item in enumerate(ps_lst):
        if (item.inst_class == PI.ASSIGNEMENT_T
            and item.inst_type == PI.NOTHING_T
            and (item.op_lst[0].type == PI.VARIABLE_T)):
                 #item.op_lst[0].type == PI.SVARIABLE_T)):
            if replace_temporals(ps_lst, pos, item.op_lst[0], item.op_lst[1]):
                item.drop = True
            else:
                item.drop = False
            


def find_further_result_op(ps_lst, start_pos, end_pos, op):
    """
    @brief Finds all assignements to op
    @param ps_lst List of PseudoInstructions
    @param start_pos Position to start searching
    @param end_pos Position to end searching
    @param op Operand for searching
    @return Returns poistion of all found assignements
    """
    positions = []
    pos = start_pos
    while pos <= end_pos:
        if ps_lst[pos].inst_class != PI.ASSIGNEMENT_T:
            break
        if ps_lst[pos].op_lst[0].name == op.name:
            positions.append(pos)
        pos += 1
    return positions


# need further testing
def reduce_ret(ps_lst):
    """
    @brief Marks all unnecessary assignemnets related to
    'ret' instruction for deletion
    @param ps_lst List of PseudoInstructions
    """
    for item in ps_lst:
        if(item.inst_type == PI.RET_T):
            break
    else: # no break
        return
    ret_addr = item.addr
    #find first item with addr
    for pos, inst in enumerate(ps_lst):
        if(inst.addr == ret_addr):
            break
    else: #no break
        return
    while pos < len(ps_lst):
        inst = ps_lst[pos]
        if inst.inst_class != PI.ASSIGNEMENT_T:
            break
        result_op = inst.op_lst[0]
        pos_lst = find_further_result_op(ps_lst,
                                    pos, len(ps_lst)-1, result_op)
        #drop all instead of the last one
        #these assignements are 'pops'
        for inst_pos in pos_lst[:len(pos_lst)-1]:
            ps_lst[inst_pos].drop = True
        #drop assignements where both ops are the same
        if result_op.name == inst.op_lst[1].name:
            ps_lst[pos].drop = True
        pos += 1



def replace_push_ebp(ps_lst, has_loc):
    """
    @brief Replaces all 'push ebp' or 'push rbp' with array operands
    @param List of PseudoInstructions
    @param has_loc Indicates if there are locals in this function
    @return List of PseudoInstructions
    """
    ret = []
    is_ret = False
    for r_item in ps_lst:
        if r_item.inst_type == PI.RET_T:
            is_ret = True
    for pos, item in enumerate(ps_lst):
        if(item.inst_type == PI.PUSH_T and
           item.op_lst[0].type == PI.REGISTER_T and
           get_reg_class(item.op_lst[0].register) == get_reg_class('ebp')):
            push_pos = last_rel_push(ps_lst, pos-1)
            if push_pos == None:
                ret.append(item)
            else:
                push_inst = ps_lst[push_pos]
                if(push_inst.list_len == 0 or
                   push_inst.addr == item.addr):#need this for saving push ebp 
                    ret.append(item)
                    continue
                push_inst_op = ps_lst[push_pos].op_lst[0]
                push_poss = scan_stack(ps_lst, pos)
                val_arr = []
                #all pos should be push so dont need a test here
                for pos in push_poss:
                    val_arr.append(ps_lst[pos].op_lst[0])
                #TODO look for better possibility
                if is_ret:
                    if (((is_mov_ebp(ps_lst, 0, pos)) and
                        is_mov_ebp(ps_lst, 0, len(ps_lst)-1)) or
                        not has_loc):
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'RET_ADDR', 0))
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'ARGS', 0))
                else:
                    if (((not is_mov_ebp(ps_lst, 0, pos)) and
                        is_mov_ebp(ps_lst, 0, len(ps_lst)-1)) or
                        not has_loc):
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'RET_ADDR', 0))
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'ARGS', 0))
                new_op = PI.ArrayOperand(
                            PI.ARRAY_T, ps_lst[push_poss[0]].size,
                            len(val_arr), val_arr)
                new_inst = PI.PseudoInstruction(
                    item.mnem, item.addr,
                    [new_op], item.size,
                    item.inst_type, item.inst_class)
                #new_inst.comment = comment
                ret.append(new_inst)
        else:
            ret.append(item)
    return ret


#just do this after reduction
def return_push_ebp(ps_lst):
    """
    @brief Replace all array operands, which are not part of an assignement,
    with 'push ebp' or 'push rbp'
    @param ps_lst List of PseudoInstructions
    @remark Just do this after 'replace_push_ebp' and 'reduce_assignements'
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.PUSH_T and
            inst.op_lst[0].type == PI.ARRAY_T):
            reg_class = get_reg_class('ebp')
            register = get_reg_by_size(reg_class, SV.dissassm_type)
            ebp_op = PI.PseudoOperand(PI.REGISTER_T, register,
                                      SV.dissassm_type, register)
            inst.op_lst[0] = ebp_op


# get pushes that are on stack between two push ebp
def scan_stack(ps_lst, s_pos):
    """
    @brief Determines which values are on the stack at a
    given 'push ebp' instruction
    @param ps_lst List of PseudoInstructions
    @param s_pos Postion of 'push ebp' or 'push rbp' instruction
    @return List of Postions
    """
    a = last_rel_push(ps_lst, s_pos-1)
    pos_lst = []
    while a != None:
        pos_lst.append(a)
        #if (#ps_lst[a].inst_type == PI.PUSH_T and
            #((ps_lst[a].op_lst[0].type == PI.REGISTER_T and
            #  get_reg_class(ps_lst[a].op_lst[0].register) == get_reg_class('ebp')) or
            #  ps_lst[a].op_lst[0].type == PI.ARRAY_T) or
            #is_mov_ebp(ps_lst, a, s_pos)):
        if is_mov_ebp(ps_lst, a, s_pos):
            pos_lst.remove(a)
            break
        a = last_rel_push(ps_lst, a-1)
    return pos_lst


def convert_read_array(ps_lst):
    """
    @brief Converts a 'vread' of an array operand to
    an assignement
    @param ps_lst List of PseudoInstructions
    @return List of PseudoInstructions
    """
    ret = []
    for inst in ps_lst:
        if inst.list_len != 2:
            ret.append(inst)
            continue
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.READ_T):
            right_op = inst.op_lst[1]
            if right_op.type != PI.ARRAY_T:
                ret.append(inst)
                continue
            left_op = inst.op_lst[0]
            new_right_op = right_op.op_val[0]
            new_inst = PI.PseudoInstruction('', inst.addr,
                [left_op, new_right_op], -1, #inst.size instead of -1 may be better
                PI.NOTHING_T, PI.ASSIGNEMENT_T)
            ret.append(new_inst)
        else:
            ret.append(inst)
    return ret


def change_nor_to_not(ps_lst):
    """
    @brief Converts a 'vnor' with two equal operands to a 'not'
    @param ps_lst List of PseudoInstructions
    @return List of PseudoInstructions
    """
    ret = []
    for inst in ps_lst:
        if inst.list_len < 3:
            ret.append(inst)
            continue
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOR_T):
            nor_op1 = inst.op_lst[1]
            nor_op2 = inst.op_lst[2]
            if nor_op1 == nor_op2:
                left_op = inst.op_lst[0]
                new_inst = PI.PseudoInstruction('vnot', inst.addr, [left_op, nor_op1], inst.size, PI.NOT_T, PI.ASSIGNEMENT_T)
                ret.append(new_inst)
            else:
                ret.append(inst)
        else:
            ret.append(inst)
    return ret


# Assumption: an add to an array pointer,
# which leaves the known stack could point
# to an argument
def scan_for_arguments(ps_lst):
    """
    @brief Searches for access to arguments
    @param ps_lst List of PseudoInstructions
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.ADD_T and
            inst.inst_class == PI.ASSIGNEMENT_T):
            array_pos = None
            imm_pos = None
            for pos, op in enumerate(inst.op_lst):
                if op.type == PI.ARRAY_T:
                    array_pos = pos
                if op.type == PI.IMMEDIATE_T:
                    imm_pos = pos
            if array_pos == None or imm_pos == None:
                continue
            imm_val = inst.op_lst[imm_pos].val
            array_op = inst.op_lst[array_pos]
            if imm_val > array_op.size * array_op.len:
                inst.comment = 'AOS: Could be Argument'


def add_comments(ps_lst):
    """
    @brief Adds comments to some instructions
    @param ps_lst List of PseudoInstructions
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.ADD_T and
            inst.inst_class == PI.ASSIGNEMENT_T):
            array_pos = None
            imm_pos = None
            for pos, op in enumerate(inst.op_lst):
                if op.type == PI.ARRAY_T:
                    array_pos = pos
                if op.type == PI.IMMEDIATE_T:
                    imm_pos = pos
            if array_pos == None or imm_pos == None:
                continue
            imm_val = inst.op_lst[imm_pos].val
            array_op = inst.op_lst[array_pos]
            has_ext = False
            for val in array_op.op_val:
                if val.type == PI.EXP_T:
                    has_ext = True
            op_len = array_op.len
            if has_ext:
                op_len -= 2
            if imm_val >= array_op.size * op_len:
                inst.comment = 'AOS: Could be Argument'
                if has_ext:
                    inst.comment += '(positive value)'
                else:
                    inst.comment += ('(push from prev BB or local variable)')

def count_left_push(ps_lst):
    """
    @brief Count left 'push' instruction for an easy lookup
    @param ps_lst List of PseudoInstructions
    """
    count = 0
    for inst in reversed(ps_lst):
        if inst.inst_type == PI.MOV_EBP_T:
            count = 0
        if inst.inst_type == PI.PUSH_T:
            inst.comment = str(count)
            count += 1


def count_left_pop(ps_lst):
    """
    @brief Count left 'pop' instruction for an easy lookup
    @param ps_lst List of PseudoInstructions
    """
    count = 0
    for inst in ps_lst:
        if inst.inst_type == PI.MOV_EBP_T:
            count = 0
        if inst.inst_type == PI.POP_T:
            inst.comment = str(count)
            count += 1

def delete_overwrote_st(ps_lst):
    """
    @brief Delete assignements to scratch variables, which are not
    relevant anymore
    @param ps_lst List of PseudoInstructions
    """
    op_pos_dict = {}
    # search for last Assignement to st variable
    for pos, inst in enumerate(ps_lst):
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOTHING_T and
            inst.op_lst[0].type == PI.SVARIABLE_T):
            op_pos_dict[inst.op_lst[0].number] = pos
    # delete all Assignements to st variable instead of the last
    for pos, inst in enumerate(ps_lst):
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOTHING_T and
            inst.op_lst[0].type == PI.SVARIABLE_T):
            left_op = inst.op_lst[0]
            if pos < op_pos_dict[left_op.number]:
                inst.drop = True


########################
# not used at mom but think about
########################
#def further_used(ps_lst, op, start_pos):
#    pos = start_pos
#    last_pos = len(ps_lst) - 1
#    while pos <= last_pos:
#        if (ps_lst[pos].drop):
#            #print 'hallo'
#            pos += 1
#            continue
#        for op_pos, r_op in enumerate(ps_lst[pos].op_lst):
#            if r_op.name == op.name:
#                return True
#        pos += 1
#    return False


#def remove_unused(ps_lst):
#    change = True
#    while change:
#        change = False
#        for pos, item in enumerate(ps_lst):
#            if item.list_len == 0:
#                continue
#            if not further_used(ps_lst, item.op_lst[0], pos + 1):
#                if item.op_lst[0].type == PI.REGISTER_T:
#                    continue
#                if not item.drop:
#                    item.drop = True
#                    change = True
#        print change
