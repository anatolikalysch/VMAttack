# -*- coding: utf-8 -*-
"""
@author: Tobias Krauss
"""

from lib.Instruction import Instruction
import lib.PseudoInstruction as PI
import lib.StartVal as SV
from lib.PseudoInstruction import (PseudoInstruction,
                               PseudoOperand)
from lib.Register import (get_reg_class,
                      get_size_by_reg,
                      get_reg_by_size)


def add_ret_pop(inst_lst):
    """
    @brief converts the 'pop' instructions of 'vret'
    to 'vpop' PseudoInstructions
    @param inst_lst List of VmInstructions
    @return List of PseudoInstructions
    """
    #find ret
    ret = []
    for vinst in inst_lst:
        if vinst.Pseudocode.inst_type == PI.RET_T:
            for inst in vinst.all_instructions:
                if inst.is_pop() and len(inst) != 1:
                    p_inst = PseudoInstruction('vpop', vinst.addr,
                                               [make_op(inst, 1, -1)])
                    ret.append(p_inst)
                elif inst.is_pop() and len(inst) == 1:
                    new_op = PseudoOperand(PI.REGISTER_T,
                                           'flags',
                                           SV.dissassm_type,
                                           'flags')
                    p_inst = PseudoInstruction('vpopf', vinst.addr,
                                               [new_op])
                    ret.append(p_inst)
            ret.append(vinst.Pseudocode)
        else:
            ret.append(vinst.Pseudocode)
    return ret


def to_vpush(p_lst, start_addr):
    """
    @brief Converts the 'push' instructions at the beginning
    of the virtual machine function to 'vpush' PseudoInstructions
    @param p_lst List of instructions
    @param start_addr Address where the PseudoInstruction must be
    placed
    @return List of PseudoInstructions
    """
    ret = []
    wrote_values = {}
    for inst in p_lst:
        if not inst.is_push():
            if inst.is_mov():
                wrote_values[inst.get_op_str(1)] = inst.get_op_str(2)
            continue
        print inst
        if len(inst) != 1:
            if inst.op_is_mem(1):
                if inst.is_rip_rel():
                    disp = inst.get_op_disp(1)
                    disp += inst.addr + inst.opcode_len
                    new_op = PseudoOperand(PI.MEMORY_T,
                                           '[{0:#x}]'.format(disp),
                                           inst.get_op_size(1),
                                           '', None)
                else:
                    new_op = PseudoOperand(PI.MEMORY_T,
                                           inst.get_op_str(1),
                                           inst.get_op_size(1),
                                           '', None)
                ret.append(PseudoInstruction('vpush',
                                             start_addr,
                                             [new_op]))
            elif inst.op_is_mem_abs(1):
                new_op = PseudoOperand(PI.MEMORY_T,
                                        inst.get_op_str(1),
                                        inst.get_op_size(1),
                                        '', None)
                ret.append(PseudoInstruction('vpush',
                                            start_addr,
                                            [new_op]))
            elif inst.op_is_reg(1):
                wrote_value = False
                if inst.get_op_str(1) in wrote_values:
                    new_op = PseudoOperand(PI.IMMEDIATE_T,
                                    wrote_values[inst.get_op_str(1)],
                                    inst.get_op_size(1),
                                    int(wrote_values[inst.get_op_str(1)], 16))
                    ret.append(PseudoInstruction('vpush',
                                                 start_addr,
                                                 [new_op]))
                else:
                    new_op = PseudoOperand(PI.REGISTER_T,
                                           inst.get_op_str(1),
                                           inst.get_op_size(1),
                                           inst.get_reg_name(1))
                    ret.append(PseudoInstruction('vpush',
                                                 start_addr,
                                                 [new_op]))
            elif inst.op_is_imm(1):
                new_op = PseudoOperand(PI.IMMEDIATE_T,
                                       inst.get_op_str(1),
                                       inst.get_op_size(1), '')
                ret.append(PseudoInstruction('vpush',
                                             start_addr,
                                             [new_op]))
        else:
            new_op = PseudoOperand(PI.REGISTER_T, 'flags',
                                   SV.dissassm_type, 'flags')
            p_inst = PseudoInstruction('vpushf', start_addr, [new_op])
            ret.append(p_inst)
    return ret


def make_op(inst, op, catch_value):
    """
    @brief convert operands to PseudoOperands
    @param inst Instruction with the Operand
    @param op number of op; op = 1 for first operand
    @param catch_value Value from the obfuscated code
    @return PseudoOperand
    """
    if(inst.get_op_str(op) == None):
        return None
    if inst.op_is_mem(op):
        return PseudoOperand(PI.MEMORY_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_reg_name(op),
                            catch_value)
    elif inst.op_is_reg(op):
        return PseudoOperand(PI.REGISTER_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_reg_name(op))
    elif inst.op_is_imm(op):
        return PseudoOperand(PI.IMMEDIATE_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_op_value(op))
    else:
        return None


def extend_signed_catch_val(reg, catch_value):
    """
    @brief Sign extends catch_value
    @param register Register which contains the catch_value
    @param catch_value Value catched form obfuscated code
    @return Sign extended catch_value
    """
    reg_size = get_size_by_reg(reg)
    if reg_size == 8 and catch_value > 0x79:
        if SV.dissassm_type == SV.ASSEMBLER_32:
            catch_value = 0xffffff00 + catch_value
        elif SV.dissassm_type == SV.ASSEMBLER_64:
            catch_value = 0xffffffffffffff00 + catch_value
        elif reg_size == 16 and catch_value > 0x7900:
            if SV.dissassm_type == SV.ASSEMBLER_32:
                catch_value = 0xffff0000 + catch_value
            elif SV.dissassm_type == SV.ASSEMBLER_64:
                catch_value = 0xffffffffffff0000 + catch_value
        elif reg_size == 32 and catch_value > 0x79000000:
            #there is nothing to do for 32bit
            if SV.dissassm_type == SV.ASSEMBLER_64:
                catch_value = 0xffffffff00000000 + catch_value
        #there is nothing to do for reg_size == 64
    return catch_value


class VmInstruction(object):
    """
    @brief Converts the exectued x86 code to the corresponding PseudoInstruction
    """


    def __init__(self, instr_lst, catch_value, catch_reg, inst_addr):
        """
        @param instr_lst List of x86 instructions
        @param catch_value Value that is catched from the virtual code
        or None if there is no value catched
        @param catch_reg Register in which the catch_value is moved
        @param inst_addr Address of the VmInstruction
        """
        self.all_instructions = instr_lst
        self.Vinstructions = []
        self.Instructions = []
        self.is_signed = False
        for inst in instr_lst:
            if inst.is_vinst():
                self.Vinstructions.append(inst)
            else:
                self.Instructions.append(inst)
        self.Pseudocode = None
        self.catch_value = catch_value
        self.catch_reg = catch_reg
        self.addr = inst_addr
        if not self.get_pseudo_code():
            mnem_str = ''
            for inst in self.all_instructions:
                mnem_str += str(inst)
            self.Pseudocode= PI.PseudoInstruction(mnem_str, inst_addr, [], 0, PI.UNDEF_T)
            print 'Did not find pseudocode at addr: {0:#x}'.format(inst_addr)


    def __str__(self):
        if self.Pseudocode is not None:
            return str(self.Pseudocode)
        else:
            inst_str = ''
            for item in self.all_instructions:
                inst_str = inst_str + str(item) + '\n'
            return inst_str


    def replace_catch_reg(self):
        """
        @brief replace the catch_register with its catch_value
        """
        if (self.catch_reg == ''):
            return
        if self.is_signed:
            self.catch_value = extend_signed_catch_val(self.catch_reg, self.catch_value)
        self.Pseudocode.replace_reg_class(self.catch_reg, self.catch_value)


    def get_pseudo_code(self):
        """
        @brief tests if its a known VmInstruction
        @remark Those tests set the Pseudocode variable with the
        corresponding PseudoInstruction
        """
        if (self.is_push() or
            self.is_pop()):
            self.replace_catch_reg()
            return True
        elif (self.is_nor() or
              self.is_add() or
              self.is_jmp() or
              self.is_write() or
              self.is_read() or
              self.is_shift_right() or
              self.is_shift_left() or
              self.is_shld() or
              self.is_shrd() or
              self.is_vcall() or
              self.is_mov_ebp() or
              self.is_vret() or
              self.is_imul() or
              self.is_idiv()):
            return True
        else:
            return False

###########################
#     helper functions    #
###########################

    def get_previous(self, method, pos):
        """
        @brief Find previous instruction for which method evaluates True
        @param method Evaluation method
        @param pos Last position
        """
        pos_lst = []
        for prev_pos, inst in enumerate(self.Instructions):
            if (prev_pos < pos) and method(inst):
                pos_lst.append(prev_pos)
        return pos_lst


    def get_subsequent(self, method, pos):
        """
        @brief Find subsequent instruction for which method evaluates True
        @param method Evaluation method
        @param pos First position
        """
        pos_lst = []
        for subs_pos, inst in enumerate(self.Instructions):
            if (subs_pos > pos) and method(inst):
                pos_lst.append(subs_pos)
        return pos_lst



########################
#  decision functions  #
########################
    def is_push(self):
        """
        @brief Tests if the VmInstruction is a 'vpush'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_sub_basepointer()):
                break
            if(get_reg_class(self.catch_reg) == get_reg_class('eax') and
               (inst.is_cwde() or inst.is_cbw() or inst.is_cdqe())):
                self.is_signed = True
        else : # no break
            return False
        pos_pmov_lst = self.get_subsequent(Instruction.is_write_stack, pos)
        if len(pos_pmov_lst) != 1:
            return False
        push_inst = self.Instructions[pos_pmov_lst[0]]
        pos_mov_lst = self.get_previous(Instruction.is_mov, pos)
        push_op = make_op(push_inst, 2, self.catch_value)
        for pos_mov in pos_mov_lst:
            pos_mov_inst = self.Instructions[pos_mov]
            if pos_mov_inst.is_read_stack():
                return False
            if((get_reg_class(push_inst.get_op_str(2)) ==
                  get_reg_class(pos_mov_inst.get_op_str(1))) and
                  get_reg_class(push_inst.get_op_str(2)) != None): # too strong condition
                push_op = make_op(pos_mov_inst, 2, self.catch_value)
        sub_value = self.Instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction('vpush', self.addr, [push_op], sub_value)
        return True


    # control in comp.vmp loc4041c8
    # size von holen und add sub gleich?
    def is_pop(self):
        """
        @brief Tests if the VmInstruction is a 'vpop'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_add_basepointer()):
                break
        else : # no break
            return False
        pos_pmov_lst = self.get_previous(Instruction.is_read_stack, pos)
        if len(pos_pmov_lst) == 0:
            return False
        for ppos in pos_pmov_lst:
            pop_inst = self.Instructions[ppos] # get last pop_mov inst in case there are more
        pop_op = make_op(pop_inst, 1, self.catch_value)
        pos_mov_lst = self.get_subsequent(Instruction.is_mov, pos)
        op_pos = ppos
        for pos_mov in pos_mov_lst:
            pos_mov_inst = self.Instructions[pos_mov]
            if(pos_mov_inst.is_write_stack()):
                return False
            if((get_reg_class(pop_inst.get_op_str(1)) ==
                  get_reg_class(pos_mov_inst.get_op_str(2))) and
                  get_reg_class(pop_inst.get_op_str(1))):  #maybe too weak
                pop_op = make_op(pos_mov_inst, 1, self.catch_value)
                op_pos = pos_mov
        if(not self.Instructions[op_pos].op_is_mem(1)):
            return False
        add_value = self.Instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction('vpop', self.addr,
                                            [pop_op], add_value)
        #print 'vpop'
        return True


    #TODO add with two regs
    def is_add(self):
        """
        @brief Tests if the VmInstruction is a 'vadd'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_add() and not inst.op_is_imm(2)):
                break
        else: # no break
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        # mit opstr?
        opstr = self.Instructions[pos].get_op_str(2)
        for pos0 in pos_mov:
            if opstr == self.Instructions[pos0].get_op_str(1):
                self.Pseudocode = PseudoInstruction('vadd', self.addr, 
                    [make_op(self.Instructions[pos], 1, self.catch_value),
                     make_op(self.Instructions[pos0], 2, self.catch_value)], SV.dissassm_type / 8)
                break
        else:
            return False
        return True


    def is_nor(self):
        """
        @brief Tests if the VmInstruction is a 'vnor'.
        If True sets the PseudoInstruction
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        and_size = 0
        for pos, inst in enumerate(self.Instructions):
            if inst.is_and():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                and_size = inst.get_mov_size()
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_not = self.get_previous(Instruction.is_not, pos)
        #if len(pos_not) < 1 or len(pos_not) > 2:
        #    return False
        not_size = 0
        for posn in pos_not:
            not_size += (self.Instructions[posn].Instruction.operands[0].size / 8)
        if(not_size != 2 * and_size):
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        #if len(pos_mov) != 2:
        #    return False
        mov_r0 = False
        mov_r1 = False
        op1 = make_op(self.Instructions[pos], 1, self.catch_value)
        op2 = make_op(self.Instructions[pos], 2, self.catch_value)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0:
            op1 = make_op(self.Instructions[pos_reg0], 2, self.catch_value)
        if mov_r1:
            op2 = make_op(self.Instructions[pos_reg1], 2, self.catch_value)
        #quick fix correct !!!
        if(op1.register == 'ebp') and (and_size == 2):
            op1 = op1.replace('+0x4', '+0x2')
        self.Pseudocode = PseudoInstruction('vnor', self.addr, [op1, op2], and_size)
        return True


    def is_jmp(self):
        """
        @brief Tests if the VmInstruction is a 'vjmp'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.all_instructions):
            if(inst.is_add_basepointer()):
                break
        else : # no break
            return False
        prev_pos = 0
        while prev_pos < pos:
            if self.all_instructions[prev_pos].is_isp_mov():
                break
            prev_pos = prev_pos + 1
        else: # no break
            return False
        add_value = self.all_instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction(
                    'vjmp', self.addr,
                    [make_op(self.all_instructions[prev_pos], 2, self.catch_value)], add_value)
        return True

    def is_write(self):
        """
        @brief Tests if the VmInstruction is a 'vwrite'.
        If True sets the PseudoInstruction
        """
        reg0 = ''
        reg1 = ''
        mov_size = 0
        sub_size = 0
        for pos, inst in enumerate(self.all_instructions):
            if inst.op_is_mem(1) and not inst.is_write_stack():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                mov_size = inst.get_mov_size()
                break
        else: # no break
            return False
        for subpos, inst in enumerate(self.Instructions):
            if(inst.is_add_basepointer()):
                sub_size = inst.get_op_value(2)
                break
        else : # no break
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            op1_inst =  self.Instructions[pos_reg0]
            op1 = PseudoOperand(PI.REFERENCE_T, op1_inst.get_op_str(2),
                                op1_inst.get_op_size(2), op1_inst.get_reg_name(2))
            op2 = make_op(self.Instructions[pos_reg1], 2, self.catch_value)
            self.Pseudocode = PseudoInstruction('vwrite', self.addr,
                        [op1, op2], mov_size, PI.WRITE_T, PI.IN2_OUT0, sub_size)
            return True
        else:
            return False


    def is_read(self):
        """
        @brief Tests if the VmInstruction is a 'vread'.
        If True sets the PseudoInstruction
        """
        reg0 = ''
        reg1 = ''
        mov_size = 0
        for pos, inst in enumerate(self.all_instructions):
            if inst.op_is_mem(2) and not inst.is_read_stack():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                mov_size = inst.get_mov_size()
                break
        else: # no break
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for prev_pos in prev_mov:
            if(get_reg_class(reg1) ==
               get_reg_class(self.Instructions[prev_pos].get_reg_name(1))):
                break
        else: # no break
            return False
        for post_pos in post_mov:
            if(get_reg_class(reg0) ==
               get_reg_class(self.Instructions[post_pos].get_reg_name(2))):
                push_size = self.Instructions[post_pos].get_mov_size()
                break
        else: # no break
            return False
        # wta = write to address
        #if mov_size == 1:
        op1 = make_op(self.Instructions[post_pos], 1, self.catch_value)
        op2_inst = self.Instructions[prev_pos]
        op2 = PseudoOperand(PI.REFERENCE_T, op2_inst.get_op_str(2),
                            op2_inst.get_op_size(2), op2_inst.get_reg_name(2))
        self.Pseudocode = PseudoInstruction('vread', self.addr,
                                            [op1, op2], mov_size, PI.READ_T, PI.IN1_OUT1 , push_size)
        return True
        

    def is_shift_right(self):
        """
        @brief Tests if the VmInstruction is a 'vshr'.
        If True sets the PseudoInstruction
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        for pos, inst in enumerate(self.Instructions):
            if inst.is_shr() and inst.op_is_reg(1) and inst.op_is_reg(2):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        if len(pos_mov) != 2:
            return False
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for save_mov in post_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[save_mov].get_reg_name(2))):
                ret_size = self.Instructions[save_mov].get_mov_size()
                break
        else: # no break
            return False
        if mov_r0 and mov_r1:
            # TODO byte word usw...
            self.Pseudocode = PseudoInstruction('vshr', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                ret_size)
            return True
        else:
            return False


    def is_shift_left(self):
        """
        @brief Tests if the VmInstruction is a 'vshl'.
        If True sets the PseudoInstruction
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        for pos, inst in enumerate(self.Instructions):
            if inst.is_shl() and inst.op_is_reg(1) and inst.op_is_reg(2):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        if len(pos_mov) != 2:
            return False
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for save_mov in post_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[save_mov].get_reg_name(2))):
                ret_size = self.Instructions[save_mov].get_mov_size()
                break
        else: # no break
            return False
        if mov_r0 and mov_r1:
            # TODO byte word usw...
            self.Pseudocode = PseudoInstruction('vshl', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                ret_size)
            return True
        else:
            return False


    def is_shrd(self):
        """
        @brief Tests if the VmInstruction is a 'vshrd'.
        If True sets the PseudoInstruction
        """
        and_found = False
        reg0 = ''
        reg1 = ''
        reg2 = ''
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_shrd() and inst.op_is_reg(1) and inst.op_is_reg(2)
                  and inst.op_is_reg(3)):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                reg2 = inst.get_reg_name(3)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos0 in prev_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[prev_pos0].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos1 in prev_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[prev_pos1].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos2 in prev_mov:
            if (get_reg_class(reg2) ==
                  get_reg_class(self.Instructions[prev_pos2].get_reg_name(1))):
                break
        else: # no break
            return False
        self.Pseudocode = PseudoInstruction('vshrd', self.addr,
                [make_op(self.Instructions[prev_pos0], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos1], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos2], 2, self.catch_value)])
        return True

    def is_shld(self):
        """
        @brief Tests if the VmInstruction is a 'vshld'.
        If True sets the PseudoInstruction
        """
        and_found = False
        reg0 = ''
        reg1 = ''
        reg2 = ''
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_shld() and inst.op_is_reg(1) and inst.op_is_reg(2)
                  and inst.op_is_reg(3)):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                reg2 = inst.get_reg_name(3)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos0 in prev_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[prev_pos0].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos1 in prev_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[prev_pos1].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos2 in prev_mov:
            if (get_reg_class(reg2) ==
                  get_reg_class(self.Instructions[prev_pos2].get_reg_name(1))):
                break
        else: # no break
            return False
        self.Pseudocode = PseudoInstruction('vshld', self.addr,
                [make_op(self.Instructions[prev_pos0], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos1], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos2], 2, self.catch_value)])
        return True


    def is_vcall(self):
        """
        @brief Tests if the VmInstruction is a 'vcall'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_call()):
                break
        else : # no break
            return False
        op1 = self.Instructions[pos].get_op_str(1)
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos in prev_mov:
            if (get_reg_class(self.Instructions[pos].get_reg_name(1)) ==
                get_reg_class(self.Instructions[prev_pos].get_reg_name(1))):
                    op1 = make_op(self.Instructions[prev_pos], 2, self.catch_value)
        self.Pseudocode = PseudoInstruction('vcall', self.addr, [op1])
        return True


    def is_vret(self):
        """
        @brief Tests if the VmInstruction is a 'vret'.
        If True sets the PseudoInstruction
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_ret()):
                break
        else : # no break
            return False
        self.Pseudocode = PseudoInstruction('vret', self.addr)
        return True


    def is_mov_ebp(self):
        """
        @brief Tests if the VmInstruction is a 'vebp_mov'.
        If True sets the PseudoInstruction
        """
        op1 = ''
        op2 = ''
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_mov() and
               get_reg_class(inst.get_reg_name(1)) == get_reg_class('ebp') and
               get_reg_class(inst.get_reg_name(2)) == get_reg_class('ebp')):
                op1 = make_op(inst, 1, self.catch_value)
                op2 = make_op(inst, 2, self.catch_value)
                break
        else : # no break
            return False
        self.Pseudocode = PseudoInstruction('vebp_mov', self.addr, [op1, op2])
        return True


    def is_imul(self):
        """
        @brief Tests if the VmInstruction is a 'vimul'.
        If True sets the PseudoInstruction
        """
        reg0 = ''
        reg1 = ''
        mul_found = False
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_imul() and inst.op_is_reg(1)):
                reg0 = inst.get_reg_name(1)
                if inst.get_reg_name(2) == None:
                    reg1 = get_reg_by_size(get_reg_class('eax'), SV.dissassm_type)
                else:
                    reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    mul_found = True
                    break
        if not mul_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            self.Pseudocode = PseudoInstruction('vimul', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                SV.dissassm_type / 8, PI.IMUL_T, PI.IN2_OUT3)
            return True
        else:
            return False


    def is_idiv(self):
        """
        @brief Tests if the VmInstruction is a 'vimul'.
        If True sets the PseudoInstruction
        """
        reg0 = ''
        reg1 = ''
        op_name = ''
        div_found = False
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_idiv()):
                reg0 = get_reg_by_size(get_reg_class('eax'), SV.dissassm_type)
                reg1 = get_reg_by_size(get_reg_class('edx'), SV.dissassm_type)
                op_name = inst.get_op_str(1)
                div_found = True
        if not div_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            self.Pseudocode = PseudoInstruction('vidiv', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value),
                 make_op(self.Instructions[pos], 1, self.catch_value)],
                SV.dissassm_type / 8, PI.DIV_T, PI.IN3_OUT3)
            return True
        else:
            return False