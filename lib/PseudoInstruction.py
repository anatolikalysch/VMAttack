#!/usr/bin/env python

"""
@author: Tobias
"""

from lib.Register import (get_reg_class,
                          get_reg_class_lst)
# get_size_by_reg)
from lib import StartVal as SV



# Operand types
REGISTER_T = 'regiser'
MEMORY_T = 'memory'
IMMEDIATE_T = 'immediate'
REFERENCE_T = 'reference'

# new Operand types
SVARIABLE_T = 'svariable'
VARIABLE_T = 'variable'
DOUBLEV_T = 'doublev'
POINTER_T = 'pointer'
ARRAY_T = 'array'
# an operand that is expect to be there
EXP_T = 'exp_t'


# Instruction types
NOTHING_T = 'nothing_T'
PUSH_T = 'push_T'
POP_T = 'pop_T'
JMP_T = 'jmp_T'
ADD_T = 'add_T'
NOR_T = 'nort_T'
READ_T = 'read_T'
WRITE_T = 'write_T'
RET_T = 'ret_T'
MOV_EBP_T = 'mov_ebp_T'
IMUL_T = 'imul_T'
DIV_T = 'div_T'

# new Instruction types
NOT_T = 'not_T'
UNDEF_T = 'undef_T'


# Instruction classes out of reversing
IN1_OUT1 = 'in1_out1'
IN1_OUT0 = 'in1_out0'
IN2_OUT0 = 'in2_out0'
IN2_OUT2 = 'in2_out2'
IN2_OUT3 = 'in2_out3'
IN3_OUT2 = 'in3_out2'
IN3_OUT3 = 'in3_out3'


# Further instruction classes
ASSIGNEMENT_T = 'assign_T'


class Operand(object):
    """
    @brief Represents an operand of a PseudoInstruction
    """

    def __init__(self, otype):
        """
        @param otype Type of the operand
        """
        self.type = otype
        self.register = ''
        self.name = ''
        self.size = 0
        self.sc_ident = False
        # self.value = None

    def __eq__(self, other):
        if (self.type == other.type and
                    self.name == other.name and
                    self.register == other.register):
            return True
        else:
            return False


class ArrayOperand(Operand):
    """
    @brief Is used for a kind of pointers
    """

    count = 0
    curr_active = 0

    def __init__(self, otype, *args):
        """
        @param otype Type of the operand
        @param *args Packed argument:
            * args[0]: Size of the operand
            * args[1]: Length of the array
            * args[2]: List of all values(some kind of operand)
            that ar in the array
        """
        Operand.__init__(self, otype)

        self.count = ArrayOperand.count
        ArrayOperand.count += 1
        self.name = 'A_' + str(self.count)
        self.size = args[0]
        self.len = args[1]
        self.op_val = args[2]
        ArrayOperand.curr_active += 1

    def __del__(self):
        if ArrayOperand.curr_active != 0:
            ArrayOperand.curr_active -= 1
        if ArrayOperand.curr_active == 0:
            ArrayOperand.count = 0

    def __eq__(self, other):
        return Operand.__eq__(self, other)

    def __str__(self):
        name = self.name + '['
        for op in self.op_val:
            size_s = self.add_size(op)
            if size_s != '':
                name += str(op) + '(' + size_s + '), '
            else:
                name += str(op) + ', '
        name = name[:len(name) - 2]
        name = name + ']'
        return name

    def add_size(self, op):
        """
        @brief Adds sizes for output to a given operand
        @param op Operand
        @return Size of op as string
        """
        size = op.size / 8
        if size == 1:
            return 'b'
        elif size == 2:
            return 'w'
        elif size == 4:
            return 'd'
        elif size == 8:
            return 'q'
        else:
            return ''


class ScratchOperand(Operand):
    """
    @brief Is used for operands in the scratch area
    """
    # dictionary contains values of all 'scretch variables'
    # scretch variables are defined by their number
    values = {}

    def __init__(self, otype, *args):
        """
        @param otype Type of the operand
        @param *args Packed argument:
            * args[0]: Location(number) of the operand
            * args[1]: Size of the operand
        """
        Operand.__init__(self, otype)
        if (args[0] != None):
            self.name = 'ST_' + str(args[0])
        else:
            self.name = 'ERROR: No catch_value found'
        self.number = args[0]
        self.size = args[1]
        ScratchOperand.values[self.number] = None
        self.own_value = None

    # def __del__(self):
    #    print 'del Sop'


    def __str__(self):
        # if not self.sc_ident:
        #    return self.name 
        # else:
        #    return ScretchOperand.values[self.number].name
        if self.own_value == None:
            return self.name
        else:
            return str(self.own_value)

    def __eq__(self, other):
        return Operand.__eq__(self, other)

    @property
    def value(self):
        return ScratchOperand.values[self.number]

    @value.setter
    def value(self, sval):
        # recursion untill threse a 'value' found
        if (sval.type == SVARIABLE_T):
            # print '........SVT:' + str(self)
            self.own_value = sval.value
        else:
            self.own_value = sval
        # ScretchOperand.values[self.number] = sval
        ScratchOperand.values[self.number] = self.own_value


class VariableOperand(Operand):
    """
    @brief Is used for temporal variables
    """

    count = 0
    curr_active = 0
    # args[0] = displacement
    def __init__(self, otype, *args):
        """
        @param otype Type of the operand
        @param *args Packed argument:
            * args[0]: Size of the operand
            * args[1]: Flag if op is Flagoperand or not
            * args[2]: Value of the operand
        """
        Operand.__init__(self, otype)
        if len(args) > 1:
            self.is_flags = args[1]
        else:
            self.is_flags = False

        if self.is_flags:
            self.count = VariableOperand.count - 1
        else:
            self.count = VariableOperand.count
            VariableOperand.count += 1
        self.name = 'T_' + str(self.count)
        self.size = args[0]
        if len(args) > 2:
            self.value = args[2]
            self.name += '(' + self.value + ')'
        VariableOperand.curr_active += 1

    def __del__(self):
        if VariableOperand.curr_active != 0:
            VariableOperand.curr_active -= 1
        if VariableOperand.curr_active == 0:
            VariableOperand.count = 0

    def __eq__(self, other):
        return Operand.__eq__(self, other)

    def __str__(self):
        if self.is_flags:
            return 'FLAGS ' + self.name
        else:
            return self.name


class DoubleVariable(Operand):
    """
    @brief Is used for instructions which have two results
    like idiv, imul
    """

    def __init__(self, left, right):
        """
        @param left The left VariableOperand
        @param right The right Variable Operand
        """
        Operand.__init__(self, DOUBLEV_T)
        self.left = left
        self.right = right

    def __str__(self):
        return str(self.left) + ':' + str(self.right)


class PseudoOperand(Operand):
    """
    @brief Is used for operands similar to x86-operands
    """

    def __init__(self, otype, *args):
        """
        @param otype Type of the operand
        @param *args Packed argument:
            * args[0]: Name of the operand
            * args[1]: Size of the operand
            * args[2]: Register/Value/Pos of the operand
            * args[3]: Displacement of the operand
        """
        Operand.__init__(self, otype)
        self.name = args[0]
        self.size = args[1]
        self.register = ''
        self.val = None
        if self.type == REGISTER_T:
            self.register = args[2]
        elif self.type == IMMEDIATE_T:
            self.val = args[2]
        elif self.type == MEMORY_T:
            self.register = args[2]
            self.displacement = args[3]
        elif self.type == REFERENCE_T:
            self.register = args[2]
            self.name = '[' + args[0] + ']'
        elif self.type == POINTER_T:
            self.pos = args[2]
            # self.name = '&' + self.name

    # def __del__(self):
    #    print 'op del'


    def __str__(self):
        if self.type == POINTER_T:
            return '&' + self.name
        else:
            return self.name

    def __eq__(self, other):
        return Operand.__eq__(self, other)

    @property
    def value(self):
        return self

    @value.setter
    def value(self, sval):
        self = sval


# @value.setter
#    def value(self, sval):
#        ScretchOperand.values[self.number] = sval


def op_min(op_lst):
    min_size = 0xffffffff
    for op in op_lst:
        if op.size < min_size:
            min_size = op.size
    return min_size


# allgemeine Vrogehensweise auf Blatt
#   name
#   addr
#   ops
#   size
#   inst_type optional
#   inst_class optional
class PseudoInstruction(object):
    """
    @brief The new representation of the instructions
    """

    def __init__(self, mnem, addr, *args):
        """
        @param mnem Mnemonic of the instruction
        @param addr Address of the instruction
        @param *args Packed argument:
            * args[0]: List of operands
            * args[1]: Size of instruction
            * args[2]: [optional] Intstructiontype of instruction
            * args[3]: [optional] Classtype of instruction
        """
        self.mnem = mnem
        self.addr = addr
        self.drop = False
        # self.is_signed = False
        self.comment = ''
        self.stack_change_size = 0
        args_len = len(args)
        if args_len > 0:
            self.op_lst = args[0]
            self.list_len = len(args[0])
        else:
            self.op_lst = []
            self.list_len = 0
        if args_len > 1:
            self.size = args[1]
        else:
            self.size = op_min(self.op_lst) / 8
        if args_len > 2:
            self.inst_type = args[2]
        else:
            self.inst_type = ''
            if (mnem == 'vpop' or
                        mnem == 'vpopf'):
                self.inst_type = POP_T
            elif (mnem == 'vpush' or
                          mnem == 'vpushf'):
                self.inst_type = PUSH_T
            elif mnem == 'vjmp':
                self.inst_type = JMP_T
            elif mnem == 'vread':
                self.inst_type = READ_T
            elif mnem == 'vwrite':
                self.inst_type = WRITE_T
            elif mnem == 'vnor':
                self.inst_type = NOR_T
            elif mnem == 'vadd':
                self.inst_type = ADD_T
            elif mnem == 'vret':
                self.inst_type = RET_T
            elif mnem == 'vebp_mov':
                self.inst_type = MOV_EBP_T
        if args_len > 3:
            self.inst_class = args[3]
        else:
            self.inst_class = ''
            if (mnem == 'vadd' or
                        mnem == 'vnor' or
                        mnem == 'vshr' or
                        mnem == 'vshl'):
                self.inst_class = IN2_OUT2
            elif (mnem == 'vshrd' or
                          mnem == 'vshld'):
                self.inst_class = IN3_OUT2
            elif (mnem == 'vread'):
                self.inst_class = IN1_OUT1
            elif (mnem == 'vwrite'):
                self.inst_class = IN2_OUT0
            elif (mnem == 'vjmp'):
                self.inst_class = IN1_OUT0
        if args_len > 4:
            self.stack_change_size = args[4]
        self.get_scratch_variable()

    def __del__(self):
        for op in self.op_lst:
            del op

    def __str__(self):
        end_str = ''
        # add assignment
        if self.inst_class == ASSIGNEMENT_T:
            if self.inst_type == WRITE_T:
                end_str += '[' + self.op_lst[0].name + '] = '
            else:
                end_str += str(self.op_lst[0]) + ' = '
        end_str += self.mnem
        # add size markers
        if self.size == 1:
            end_str += '_b '
        elif self.size == 2:
            end_str += '_w '
        elif self.size == 4:
            end_str += '_d '
        elif self.size == 8:
            end_str += '_q '
        elif self.inst_class != ASSIGNEMENT_T:
            end_str += ' '
        for pos, op in enumerate(self.op_lst):
            if (self.inst_class == ASSIGNEMENT_T and pos == 0):
                continue
            if self.inst_type == READ_T and self.inst_class == ASSIGNEMENT_T:
                end_str = end_str + '[' + str(op) + ']' + ', '
            else:
                end_str = end_str + str(op) + ', '
        if (self.list_len != 0):
            end_str = end_str[0:len(end_str) - 2] + '\n'
        else:
            end_str += '\n'
        end_str = end_str.replace('+0x0', '')
        return end_str

    def get_scratch_variable(self):
        """
        @brief Replace memory operands from 'vpush' and 'vpop' with
        ScratchOperands
        """
        if (self.inst_type != POP_T and
                    self.inst_type != PUSH_T and self.list_len != 1):
            return
        op0 = self.op_lst[0]
        if (op0.type == MEMORY_T and
                    get_reg_class(op0.register) == get_reg_class('edi')):
            self.op_lst[0] = ScratchOperand(SVARIABLE_T,
                                            op0.displacement, op0.size)

    def replace_reg_class(self, rreg, catch_value):
        """
        @brief Replace register of evrey op with catch_value
        if it is in the same register class as rreg
        @param rreg Register to replace
        @param catch_value Value that replaces the register 
        """
        reg_class = get_reg_class(rreg)
        for reg in reversed(get_reg_class_lst(reg_class)):
            for op in self.op_lst:
                if op.type == REGISTER_T and op.register == reg:
                    op.type = IMMEDIATE_T
                    op.val = catch_value
                    op.name = op.name.replace(reg,
                                              '{0:#x}'.format(catch_value))
                elif op.type == MEMORY_T and reg in op.name:
                    op.displacement = catch_value
                    op.name = op.name.replace(reg,
                                              '{0:#x}'.format(catch_value))

    # maybe better in vmInstruction combined with add_ret_pop
    def make_pop_push_rep(self):
        """
        @brief Replace plain VmInstruction representation with a
        push/pop representation. This representation needs temporal
        variables and each of these temporal variables is unique
        """
        ret = []
        if self.inst_class == IN2_OUT2:
            op0 = VariableOperand(VARIABLE_T, self.op_lst[0].size)
            op1 = VariableOperand(VARIABLE_T, self.op_lst[1].size)
            op0_size = self.op_lst[0].size / 8
            # vm does not support byte pop/push maybe worng place for this
            if op0_size < 2:
                op0_size = 2
            op1_size = self.op_lst[1].size / 8
            if op1_size < 2:
                op1_size = 2
            ret.append(PseudoInstruction('vpop', self.addr,
                                         [op0], op0_size, POP_T))
            ret.append(PseudoInstruction('vpop', self.addr, [op1],
                                         op1_size, POP_T))
            assign_op = VariableOperand(VARIABLE_T, self.size)
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr,
                [assign_op, op0, op1], self.size,
                self.inst_type, ASSIGNEMENT_T
            )
            ret.append(assign_instruction)
            flagsop = VariableOperand(VARIABLE_T, self.size, True)
            ret.append(PseudoInstruction('vpush', self.addr, [assign_op],
                                         self.op_lst[0].size / 8, PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr, [flagsop],
                                         SV.dissassm_type / 8, PUSH_T))
            return ret
        elif self.inst_class == IN2_OUT3:
            op0 = VariableOperand(VARIABLE_T, self.op_lst[0].size)
            op1 = VariableOperand(VARIABLE_T, self.op_lst[1].size)
            op0_size = self.op_lst[0].size / 8
            # vm does not support byte pop/push maybe worng place for this
            if op0_size < 2:
                op0_size = 2
            op1_size = self.op_lst[1].size / 8
            if op1_size < 2:
                op1_size = 2
            ret.append(PseudoInstruction('vpop', self.addr, [op0],
                                         op0_size, POP_T))
            ret.append(PseudoInstruction('vpop', self.addr, [op1],
                                         op1_size, POP_T))
            assign_op = VariableOperand(VARIABLE_T, self.size)
            flagsop = VariableOperand(VARIABLE_T, self.size, True)
            assign_op2 = VariableOperand(VARIABLE_T, self.size)
            double_assign = DoubleVariable(assign_op2, assign_op)
            # print 'POP PUSH REP::::::', self.size
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr,
                [double_assign, op0, op1],
                self.size, self.inst_type, ASSIGNEMENT_T)
            ret.append(assign_instruction)
            flagsop2 = VariableOperand(VARIABLE_T, self.size, True)
            double_flags = DoubleVariable(flagsop, flagsop2)
            ret.append(PseudoInstruction('vpush', self.addr, [assign_op],
                                         self.op_lst[0].size / 8, PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr, [assign_op2],
                                         self.op_lst[0].size / 8, PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr, [double_flags],
                                         SV.dissassm_type / 8, PUSH_T))
            return ret
        elif self.inst_class == IN3_OUT3:
            op_divisor = VariableOperand(VARIABLE_T, self.op_lst[2].size)
            op0 = VariableOperand(VARIABLE_T, self.op_lst[0].size)
            op1 = VariableOperand(VARIABLE_T, self.op_lst[1].size)
            op0_size = self.op_lst[0].size / 8
            # vm does not support byte pop/push maybe worng place for this
            if op0_size < 2:
                op0_size = 2
            op1_size = self.op_lst[1].size / 8
            if op1_size < 2:
                op1_size = 2
            opd_size = self.op_lst[2].size / 8
            if opd_size < 2:
                opd_size = 2
            ret.append(PseudoInstruction('vpop', self.addr, [op0],
                                         op0_size, POP_T))
            ret.append(PseudoInstruction('vpop', self.addr, [op1],
                                         op1_size, POP_T))
            ret.append(PseudoInstruction('vpop', self.addr, [op_divisor],
                                         opd_size, POP_T))
            assign_op = VariableOperand(VARIABLE_T, self.size)
            flagsop = VariableOperand(VARIABLE_T, self.size, True)
            assign_op2 = VariableOperand(VARIABLE_T, self.size)
            double_op = DoubleVariable(assign_op, assign_op2)
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr,
                [double_op, op0, op1, op_divisor], self.size,
                self.inst_type, ASSIGNEMENT_T
            )
            ret.append(assign_instruction)
            flagsop2 = VariableOperand(VARIABLE_T, self.size, True)
            double_flags = DoubleVariable(flagsop, flagsop2)
            ret.append(PseudoInstruction('vpush', self.addr,
                                         [assign_op2], self.op_lst[0].size / 8,
                                         PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr,
                                         [assign_op], self.op_lst[0].size / 8,
                                         PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr, [double_flags],
                                         SV.dissassm_type / 8, PUSH_T))
            return ret
        elif self.inst_class == IN1_OUT0:
            op_inst = None
            assign_instruction = None
            if self.inst_type == JMP_T:
                op = VariableOperand(VARIABLE_T, self.size)
                op_inst = PseudoInstruction('vpop', self.addr,
                                            [op], self.size, POP_T)
                assign_instruction = PseudoInstruction(
                    self.mnem, self.addr, [op],
                    self.size, self.inst_type, self.inst_class
                )
            else:
                # not implemented dont need so far
                op = VariableOperand(VARIABLE_T, self.op_lst[0].size)
                op_inst = PseudoInstruction('vpop', self.addr, [op],
                                            self.op_lst[0].size / 8, POP_T)
                assign_instruction = self
            ret.append(op_inst)
            ret.append(assign_instruction)
            return ret
        elif self.inst_class == IN1_OUT1:
            for pos, op in enumerate(self.op_lst):
                if (op.type == REFERENCE_T):
                    break
            else:  # no break
                # should not happen
                ret.append(self)
                return ret
            op0 = VariableOperand(VARIABLE_T, self.op_lst[pos].size)
            ret.append(PseudoInstruction('vpop', self.addr, [op0],
                                         self.op_lst[pos].size / 8, POP_T))
            assign_op = VariableOperand(VARIABLE_T, self.size)
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr, [assign_op, op0], self.size,
                self.inst_type, ASSIGNEMENT_T
            )
            ret.append(assign_instruction)
            if self.inst_type == READ_T:
                ret.append(PseudoInstruction('vpush', self.addr,
                                             [assign_op], self.stack_change_size, PUSH_T))
            else:
                ret.append(PseudoInstruction('vpush', self.addr, [assign_op],
                                             self.op_lst[pos].size / 8, PUSH_T))
            return ret
        elif self.inst_class == IN2_OUT0:
            for pos, op in enumerate(self.op_lst):
                if (op.type == REFERENCE_T):
                    break
            else:  # no break
                # should not happen
                ret.append(self)
                return ret
            assign_op = None
            op = None
            if pos == 0:
                assign_op = VariableOperand(VARIABLE_T, self.op_lst[0].size)
                op = VariableOperand(VARIABLE_T, self.op_lst[1].size)
            else:
                assign_op = VariableOperand(VARIABLE_T, self.op_lst[1].size)
                op = VariableOperand(VARIABLE_T, self.op_lst[0].size)
            # there are no pushes and pops with size 1
            op_min_size = (self.stack_change_size * 8) - assign_op.size
            if op_min_size > 0:
                op.size = op_min_size
            ret.append(PseudoInstruction('vpop', self.addr, [assign_op],
                                         assign_op.size / 8, POP_T))
            ret.append(PseudoInstruction('vpop', self.addr, [op],
                                         op.size / 8, POP_T))
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr, [assign_op, op],
                self.size, self.inst_type, ASSIGNEMENT_T
            )
            ret.append(assign_instruction)
            return ret
        elif self.inst_class == IN3_OUT2:
            op0 = VariableOperand(VARIABLE_T, self.op_lst[0].size)
            op1 = VariableOperand(VARIABLE_T, self.op_lst[1].size)
            op2 = VariableOperand(VARIABLE_T, self.op_lst[2].size)
            op2_size = self.op_lst[0].size / 8
            if op2_size < 2:
                op0_size = 2 * 8
            assign_op = VariableOperand(VARIABLE_T, self.size)
            assign_instruction = PseudoInstruction(
                self.mnem, self.addr, [assign_op, op0, op1, op2],
                self.op_lst[0].size / 8, self.inst_type, ASSIGNEMENT_T
            )
            ret.append(PseudoInstruction('vpush', self.addr, [assign_op],
                                         self.op_lst[0].size / 8, PUSH_T))
            ret.append(PseudoInstruction('vpush', self.addr, [flagsop],
                                         SV.dissassm_type / 8, PUSH_T))
        else:
            ret.append(self)
            return ret


            ##########
            # to delete
            ##########


            ##think about having a top level function
            # @staticmethod
            # def expand_reg(sreg, size = 32):
            #    reg_class = get_reg_class(sreg)
            #    return get_reg_by_size(reg_class, size)


            #    def contains_reg(self, reg):
            #        #if (reg in self.Op1) or (reg in self.Op2):
            #        return True



            #    def replace(self, catch_reg, catch_value):
            #        if catch_reg in self.Op1:
            #            self.Op1 = self.Op1.replace(catch_reg, '{0:#x}'.format(catch_value))
            #        elif catch_reg in self.Op2:
            #            self.Op2 = self.Op2.replace(catch_reg, '{0:#x}'.format(catch_value))
            #        else:
            #            return None
