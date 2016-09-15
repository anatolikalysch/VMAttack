# -*- coding: utf-8 -*-
"""
@author: Tobias
"""

import distorm3

from lib import StartVal as SV


class Instruction(object):
    """
    @brief Implements the interface to distorm3 Instructions
    """

    def __init__(self, offset, code, type = distorm3.Decode32Bits, feature = 0):
        """
        @param offset Address of the instruction
        @param code Opcode bytes of the instruction
        @param type Dissassemble 32 or 64 bit code
        @param feature Possible settings for distrom3
        not used at the moment
        """
        self.valid = False
        if SV.dissassm_type == 64:
            type = distorm3.Decode64Bits
        else:
            type = distorm3.Decode32Bits
        inst = distorm3.Decompose(offset, code, type, feature)
        if len(inst) == 1:
            self.Instruction = inst[0]
            if self.Instruction.valid:
                self.valid = True
        self.opcode_len = len(code)
        self.opcode_bytes = []
        self.addr = offset
        for x in code:
            self.opcode_bytes.append(ord(x))
        self._len = len(self.Instruction.operands) + 1 


    def __str__(self):
        return str(self.Instruction).lower()


    def __len__(self):
        return self._len


    def is_catch_instr(self):
        """
        @brief Tests if the instruction fetches
        more bytes form the obfuscated code
        @return True/False
        """
        if len(self.Instruction.operands) != 2:
            return False
        if (self.is_mov() and
            self.Instruction.operands[1].type == distorm3.OPERAND_MEMORY and
            self.Instruction.operands[0].type == distorm3.OPERAND_REGISTER):
            reg_index = self.Instruction.operands[1].index 
            if reg_index != None:
                reg_name = distorm3.Registers[reg_index]
                #change to reverserers input
                if('ESI' in reg_name or 'RSI' in reg_name):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False



    def is_mov(self):
        """
        @brief Test if the instruction is a mov
        """
        mnem = distorm3.Mnemonics[self.Instruction.opcode]
        return ('MOV' in mnem) and (self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_byte_mov(self):
        """
        @brief Tests if a mov moves one byte
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        return (self.Instruction.operands[0].size == 8 or
                                  self.Instruction.operands[1].size == 8)


    def is_word_mov(self):
        """
        @brief Tests if a mov moves two byte
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
           return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 16 and sizeOp2 >= 16):
            return True
        elif (sizeOp1 >= 16 and sizeOp2 == 16):
            return True
        else:
            return False



    def is_double_mov(self):
        """
        @brief Tests if a mov moves four byte
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 32 and sizeOp2 >= 32):
            return True
        elif (sizeOp1 >= 32 and sizeOp2 == 32):
            return True
        else:
            return False


    def is_quad_mov(self):
        """
        @brief Tests if a mov moves eight byte
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 64 and sizeOp2 >= 64):
            return True
        elif (sizeOp1 >= 64 and sizeOp2 == 64):
            return True
        else:
            return False


    def get_mov_size(self):
        """
        @brief Determines how many bytes are moved
        @return size in bytes
        """
        if self.is_quad_mov():
            return 8
        elif self.is_double_mov():
            return 4
        elif self.is_word_mov():
            return 2
        elif self.is_byte_mov():
            return 1
        else:
            return None


    def get_size(self):
        """
        @brief Easy access to size of distorm3 instruction
        """
        return self.Instruction.size


    def is_mov_basep_stackp(self):
        """
        @brief Tests if the instruction is 'mov ebp, esp' or
        'mov rbp, rsp'
        """
        if len(self.Instruction.operands) != 2:
            return False
        Op0 = self.Instruction.operands[0]
        Op1 = self.Instruction.operands[1]
        if (Op0.type == distorm3.OPERAND_REGISTER and
            Op1.type == distorm3.OPERAND_REGISTER and
            (Op0.name == 'EBP' or Op0.name == 'RBP') and
            (Op1.name == 'ESP' or Op1.name == 'RSP')):
            return True
        else:
            return False

    def is_write_stack(self):
        """
        @brief Tests if the instruction writes to
        the stack
        """
        if len(self.Instruction.operands) != 2:
            return False
        op0 = self.Instruction.operands[0]
        if op0.index == None or op0.disp != 0:
            return False
        if (self.is_mov() and
            op0.type == distorm3.OPERAND_MEMORY and
            (distorm3.Registers[op0.index] == 'EBP' or
             distorm3.Registers[op0.index] == 'RBP')):
            return True
        else:
            return False


    def is_read_stack(self):
        """
        @brief Tests if the instruction reads from
        the stack
        """
        if len(self.Instruction.operands) != 2:
            return False
        op1 = self.Instruction.operands[1]
        if op1.index == None or op1.disp != 0:
            return False
        if (self.is_mov() and
            op1.type == distorm3.OPERAND_MEMORY and
            (distorm3.Registers[op1.index] == 'EBP' or
             distorm3.Registers[op1.index] == 'RBP')):
            return True
        else:
            return False


    def is_isp_mov(self):
        """
        @brief Tests if the instructionpoiter of the vm
        gets a new value
        """
        if len(self.Instruction.operands) != 2:
            return False
        op0 = self.Instruction.operands[0]
        if op0.index == None:
            return False
        if (self.is_mov() and
            op0.type == distorm3.OPERAND_REGISTER and
            (distorm3.Registers[op0.index] == 'ESI' or
             distorm3.Registers[op0.index] == 'RSI')):
            return True
        else:
            return False


    #first op is 1 secend 2 and so on
    def op_is_reg(self, op):
        """
        @brief Tests if a operand of a instruction is a
        register
        @param op Access to operand; for first operand: op = 1
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_REGISTER


    def op_is_imm(self, op):
        """
        @brief Tests if a operand of a instruction is a
        immediate
        @param op Access to operand; for first operand: op = 1
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_IMMEDIATE


    def op_is_mem(self, op):
        """
        @brief Tests if a operand of a instruction is a
        memory access
        @param op Access to operand; for first operand: op = 1
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_MEMORY


    def op_is_mem_abs(self, op):
        """
        @brief Tests if a operand of a instruction is a
        is a memory access through an absolute address
        @param op Access to operand; for first operand: op = 1
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_ABSOLUTE_ADDRESS


    def is_vinst(self):
        """
        @brief Tests if one of the operands of the instruction is
        the 'esi' or 'rsi' register
        """
        for op in self.Instruction.operands:
            if op.type == distorm3.OPERAND_REGISTER:
                if op.name == 'ESI' or op.name == 'RSI':
                    return True
            elif op.type == distorm3.OPERAND_MEMORY:
                if op.index != None:
                    if (distorm3.Registers[op.index] == 'ESI' or
                        distorm3.Registers[op.index] == 'RSI'):
                        return True
        return False


    def is_ret(self):
        """
        @brief Tests if the instruction is a 'ret'
        """
        return self.Instruction.flowControl == 'FC_RET'


    def is_call(self):
        """
        @brief Tests if the instruction is a 'call'
        """
        return (self.Instruction.mnemonic.startswith('CALL') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_and(self):
        """
        @brief Tests if the instruction is a 'and'
        """
        return (self.Instruction.mnemonic.startswith('AND') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shr(self):
        """
        @brief Tests if the instruction is a 'shr'
        """
        return (self.Instruction.mnemonic == 'SHR' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shl(self):
        """
        @brief Tests if the instruction is a 'shl'
        """
        return (self.Instruction.mnemonic == 'SHL' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shld(self):
        """
        @brief Tests if the instruction is a 'shld'
        """
        return (self.Instruction.mnemonic == 'SHLD' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shrd(self):
        """
        @brief Tests if the instruction is a 'shrd'
        """
        return (self.Instruction.mnemonic == 'SHRD' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_cwde(self):
        """
        @brief Tests if the instruction is a 'cwde'
        """
        return self.Instruction.mnemonic == 'CWDE'


    def is_cbw(self):
        """
        @brief Tests if the instruction is a 'cbw'
        """
        return self.Instruction.mnemonic == 'CBW'


    def is_cdqe(self):
        """
        @brief Tests if the instruction is a 'cbw'
        """
        return self.Instruction.mnemonic == 'CDQE'

    def is_imul(self):
        """
        @brief Tests if the instruction is a 'imul'
        """
        return self.Instruction.mnemonic == 'IMUL'


    def is_idiv(self):
        """
        @brief Tests if the instruction is a 'idiv'
        """
        return self.Instruction.mnemonic == 'IDIV'


    def is_add(self):
        """
        @brief Tests if the instruction is a 'add'
        """
        return (self.Instruction.mnemonic.startswith('ADD') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_not(self):
        """
        @brief Tests if the instruction is a 'not'
        """
        return (self.Instruction.mnemonic.startswith('NOT') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_pop(self):
        """
        @brief Tests if the instruction is a 'pop'
        """
        return (self.Instruction.mnemonic == 'POP' or
                self.Instruction.mnemonic == 'POPF')


    def is_push(self):
        """
        @brief Tests if the instruction is a 'push'
        """
        return (self.Instruction.mnemonic == 'PUSH' or
                self.Instruction.mnemonic == 'PUSHF')


    def is_uncnd_jmp(self):
        """
        @brief Tests if the instruction is an unconditional jump
        """
        return self.Instruction.flowControl == 'FC_UNC_BRANCH'


    def is_sub_basepointer(self):
        """
        @brief Tests if the instruction subtracts something from
        the basepointer
        """
        return (('SUB' in self.Instruction.mnemonic) and
                (self.Instruction.instructionClass == 'ISC_INTEGER') and
                (self.Instruction.operands[0].name == 'EBP' or
                 self.Instruction.operands[0].name == 'RBP'))


    def is_add_basepointer(self):
        """
        @brief Tests if the instruction adds something to the
        basepointer
        """
        return (('ADD' in self.Instruction.mnemonic) and
                (self.Instruction.instructionClass == 'ISC_INTEGER') and
                (self.Instruction.operands[0].name == 'EBP' or
                 self.Instruction.operands[0].name == 'RBP'))


    def get_op_str(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the string represtentation of op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return str(self.Instruction.operands[op-1]).lower()


    def get_op_size(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the size of op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return self.Instruction.operands[op-1].size


    def get_reg_name(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the name of the register from op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_reg(op):
            return self.Instruction.operands[op-1].name.lower()
        elif self.op_is_mem(op):
            #abfrage
            return distorm3.Registers[self.Instruction.operands[op-1].index]
        else:
            return None


    def get_op_value(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the value of op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_imm(op):
            return self.Instruction.operands[op-1].value
        else:
            return None


    def get_op_disp(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the displacement of op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_mem_abs(op) or self.op_is_mem(op):
            return self.Instruction.operands[op-1].disp
        else:
            return None


    def get_op(self, op):
        """
        @param op Access to operand; for first operand: op = 1
        @return Returns the distorm3 op
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return self.Instruction.operands[op-1]


    def is_rip_rel(self):
        """
        @brief tests if the address is relativ to 'rip'
        """
        return 'FLAG_RIP_RELATIVE' in self.Instruction.flags

