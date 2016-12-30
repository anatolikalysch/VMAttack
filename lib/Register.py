#!/usr/bin/env python

"""
@author: Tobias
"""

"""@brief List of register classes"""
_registerClasses = [
    ['al', 'ah', 'ax', 'eax', 'rax'],
    ['bl', 'bh', 'bx', 'ebx', 'rbx'],
    ['cl', 'ch', 'cx', 'ecx', 'rcx'],
    ['dl', 'dh', 'dx', 'edx', 'rdx'],
    ['bpl', 'bp', 'ebp', 'rbp'],
    ['dil', 'di', 'edi', 'rdi'],
    ['sil', 'si', 'esi', 'rsi'],
    ['spl', 'sp', 'esp', 'rsp'],
    ['r8l', 'r8w', 'r8d', 'r8'],
    ['r9l', 'r9w', 'r9d', 'r9'],
    ['r10l', 'r10w', 'r10d', 'r10'],
    ['r11l', 'r11w', 'r11d', 'r11'],
    ['r12l', 'r12w', 'r12d', 'r12'],
    ['r13l', 'r13w', 'r13d', 'r13'],
    ['r14l', 'r14w', 'r14d', 'r14'],
    ['r15l', 'r15w', 'r15d', 'r15']
    ]


def get_reg_class(reg):
    """
    @brief Determines the register class of a given reg.
    All different register names that address the same register
    belong to the same register class e.g.: 'ax' and 'eax'
    @param reg name of register
    @return register class
    """
    lreg = reg.lower()
    ret_value = None
    for pos, reg_list in enumerate(_registerClasses):
        for reg in reg_list:
            found = False
            if reg == lreg:
                found = True
                ret_value = pos
                break
        if found:
            break
    return ret_value


def get_reg_by_size(reg_class, reg_size):
    """
    @brief Determines the register by its size and class
    @param reg_class The register class of the register
    @param reg_size The size of the register
    @return Name of the register
    """
    if reg_class >= len(_registerClasses):
        return None
    num_regs = len(_registerClasses[reg_class])
    if num_regs < 4:
        return None
    reg_index = -1
    if reg_size > 32: # 64-bit regs
        reg_index = num_regs - 1
    elif reg_size > 16: # 32-bit regs
        reg_index = num_regs - 2
    elif reg_size > 8: # 16-bit regs
        reg_index = num_regs - 3
    elif reg_size > 0: # 8-bit regs
        reg_index = 0
    else:
        return None
    return _registerClasses[reg_class][reg_index]


def get_size_by_reg(reg):
    """
    @brief Determines the size of the given register
    @param reg Register
    @return Size of register
    """
    reg_class = get_reg_class(reg)
    num_regs = len(_registerClasses[reg_class])
    for index, test_reg in enumerate(_registerClasses[reg_class]):
        if test_reg == reg:
            break
    else: # no break
        return None
    if index == (num_regs-1):
        return 64
    elif index == (num_regs-2):
        return 32
    elif index == (num_regs-3):
        return 16
    else:
        return 8



def get_reg_class_lst(reg_class):
    """
    @return Returns the whole list of a given register class 
    """
    return _registerClasses[reg_class]
