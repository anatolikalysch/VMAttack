# -*- coding: utf-8 -*-
"""
@author: Tobias Krauss, Anatoli Kalysch
"""
from idaapi import *
from idautils import *
from idc import *
from lib.Instruction import Instruction
from lib.Optimize import *
from lib.Register import (get_reg_by_size,
                          get_reg_class)
from lib.VmInstruction import VmInstruction
from lib.VmInstruction import (add_ret_pop,
                               to_vpush)

# import PseudoInstruction as PI
import distorm3
import lib.PseudoInstruction as PI
import lib.StartVal as SV
from ui.BBGraphViewer import show_graph
from lib.VMRepresentation import VMContext, get_vmr

bb_colors = [0xddddff, 0xffdddd, 0xddffdd, 0xffddff, 0xffffdd, 0xddffff]


def calc_code_addr(instr, base):
    """
    @param instr: Bytecode of a instruction of the virtual machine.
    @param base: Address of the jumptable of the virtual machine.
    @return Address of the executed x86 code
    """
    if SV.dissassm_type == SV.ASSEMBLER_32:
        return Dword((instr * 4) + base)
    else:
        return Qword((instr * 8) + base)


def get_instruction_list(vc, base):
    """
    @brief Generates a list of the executed x86 instructions for the
    given virtuel instruction (vc)
    @param vc: Bytecode of a instruction of the virtual machine.
    @param base: Address of the jumptable of the virtual machine.
    @return List of executed x86 instructions
    """
    inst_addr = calc_code_addr(vc, base)
    if not isCode(GetFlags(inst_addr)):
        MakeUnknown(inst_addr, 1, DOUNK_SIMPLE)
        MakeCode(inst_addr)
    inst_lst = []
    end_of_instruction_block = False
    while not end_of_instruction_block:
        size = ItemSize(inst_addr)
        inst_bytes = GetManyBytes(inst_addr, size)
        inst = Instruction(inst_addr, inst_bytes)
        if inst.is_uncnd_jmp():
            end_of_instruction_block = True
        elif inst.is_ret():
            inst_lst.append(inst)
            end_of_instruction_block = True
        else:
            inst_lst.append(inst)
            inst_addr = NextHead(inst_addr)
    return inst_lst


def clear_comments(ea, endaddr):
    """
    @brief Can be started from ida-python-shell.
    Clears all comments form ea to endaddr
    @param ea: Startaddress to remove comments
    @param endaddr: Endaddress
    """
    while ea <= endaddr:
        MakeComm(ea, "")
        ea = ea + 1


def get_start_push(vm_addr):
    """
    @brief Generates a list of the first instructions from the
    virtual machine
    @param vm_addr Address of the virtual machine function
    @return List of instructions
    """
    inst_addr = vm_addr
    ret = []
    end_of_instruction_block = False
    while not end_of_instruction_block:
        size = ItemSize(inst_addr)
        inst_bytes = GetManyBytes(inst_addr, size)
        inst = Instruction(inst_addr, inst_bytes)
        if inst.is_mov_basep_stackp():
            end_of_instruction_block = True
        else:
            inst_addr = NextHead(inst_addr)
            ret.append(inst)
    return ret


jump_dict = {}


def get_catch_reg(reg, length):
    """
    @brief Determines the right catch register for further usage
    @param reg Register from x86 code
    @param length Move size of catch instruction in bytes
    @return Register with right size or empty string
    """
    reg_class = get_reg_class(reg)
    if reg_class == None:
        return ''
    catch_reg = get_reg_by_size(reg_class, length * 8)
    if catch_reg == None:
        catch_reg = ''
    return catch_reg


def first_deobfuscate(ea, base, endaddr):
    """
    @brief Converts virtual code between ea and endaddr to VmInstructions
    @param ea Startaddress of virtual code
    @param base Address of the jumptable of the virtual machine.
    @param endaddr Endaddress of virtual code
    @return List of all VmInstructions between ea and endaddr
    """
    curraddr = ea
    instr_lst = []
    vminst_lst = []
    catch_value = None
    while curraddr <= endaddr:
        inst_addr = curraddr
        vc = Byte(curraddr)
        instr_lst = get_instruction_list(vc, base)
        if len(instr_lst) < 1:
            print 'error occured'
            curraddr += 1
            continue
        has_catch = False
        catch_instr = None
        for pos, inst in enumerate(instr_lst):
            if inst.is_catch_instr():
                catch_instr = inst
                has_catch = True
                break
        if has_catch:
            if catch_instr.is_byte_mov():
                catch_value = Byte(curraddr + 1)
                length = 2
            elif catch_instr.is_word_mov():
                catch_value = Word(curraddr + 1)
                length = 3
            elif catch_instr.is_double_mov():
                catch_value = Dword(curraddr + 1)
                length = 5
            elif catch_instr.is_quad_mov():
                catch_value = Qword(curraddr + 1)
                length = 9
        else:
            length = 1
        curraddr += length
        MakeUnknown(inst_addr, length, DOUNK_SIMPLE)
        if has_catch:
            catch_reg = get_catch_reg(catch_instr.get_op_str(1), length - 1)
        else:
            catch_reg = ''
        vm_inst = VmInstruction(instr_lst, catch_value,
                                catch_reg, inst_addr)
        vminst_lst.append(vm_inst)
        if (vm_inst.Pseudocode == None):
            continue
        if (vm_inst.Pseudocode.inst_type == PI.JMP_T or
                    vm_inst.Pseudocode.inst_type == PI.RET_T):
            if isCode(GetFlags(curraddr)):
                if curraddr in jump_dict:
                    curraddr = jump_dict[curraddr]
                    continue
                Jump(curraddr)
                answer = AskYN(0,
                               ('Should this regular x86 at address ' +
                                '{0:#x} instructions be deobfuscated?'.format(curraddr)))
                if answer == 0 or answer == -1:
                    old_addr = curraddr
                    curraddr = AskAddr(curraddr,
                                       'Insert Address where deobfuscation will be continued!')
                    jump_dict[old_addr] = curraddr
    return vminst_lst


def deobfuscate_all(base):
    """
    @brief Converts every possible virtual code to VmInstructions
    @param base Address of the jumptable of the virtual machine.
    @return List of all possible VmInstructions
    @remark This function is not used for deobfuscate the virtual code,
    its just a test if every possible virtual instruction is translated
    properly.
    """
    catch_byte = 0x00
    vm_inst_lst = []
    while catch_byte <= 0xff:
        inst_lst = get_instruction_list(catch_byte, base)
        vm_inst = VmInstruction(inst_lst, 0x0, '',
                                (SV.dissassm_type / 8 * catch_byte) + base)
        vm_inst.get_pseudo_code()
        vm_inst_lst.append(vm_inst)
        catch_byte += 1
    return vm_inst_lst


def display_ps_inst(ps_inst_lst):
    """
    @brief Displays PseudoInstructions in the comments of Ida
    @param ps_inst_lst List of PseudoInstructions
    """
    length = len(ps_inst_lst)
    comm = ''
    for pos, item in enumerate(ps_inst_lst):
        if pos < length - 1:
            addr = item.addr
            next_addr = ps_inst_lst[pos + 1].addr
        else:
            addr = item.addr
            next_addr = item.addr + 1
        if addr == next_addr:
            comm += str(item)[:len(str(item)) - 1] + '\t\t' + item.comment + '\n'
        else:
            comm += str(item)[:len(str(item)) - 1] + '\t\t' + item.comment + '\n'
            MakeComm(addr, comm)
            comm = ''


def display_vm_inst(vm_inst_lst):
    """
    @brief Displays VirtualInstructions in the comments of Ida
    @param vm_inst_lst List of VirtualInstructions
    """
    length = len(vm_inst_lst)
    comm = ''
    for pos, item in enumerate(vm_inst_lst):
        if pos < length - 1:
            addr = item.addr
            next_addr = vm_inst_lst[pos + 1].addr
        else:
            addr = item.addr
            next_addr = item.addr + 1
        if addr == next_addr:
            comm += str(item)[:len(str(item)) - 1] + '\n'
        else:
            comm += str(item)[:len(str(item)) - 1] + '\n'
            MakeComm(addr, comm)
            comm = ''


def read_in_comments(start, end):
    """
    @brief Read in all ida comments between start and end
    @param start Address where to start reading
    @param end Address where to end reading
    @return List of Tuples (comment, address of comment)
    """
    ret = []
    addr = start
    while addr <= end:
        comment = CommentEx(addr, 0)
        r_comment = CommentEx(addr, 1)
        if comment == None and r_comment == None:
            addr += 1
        elif r_comment == None and comment != None:
            ret.append((comment, addr))
            addr += 1
        elif r_comment != None and comment == None:
            print 'r_comment'
            ret.append((r_comment, addr))
            addr += 1
        else:
            erg_comm = r_comment + '\n' + comment
            ret.append((erg_comm, addr))
            addr += 1
    return ret


def find_start(start, end):
    """
    @brief tries to find startaddress of function due to
    crossrefernces
    
    @param start Startaddress of searching
    @param end Endaddress
    @return Startaddress of obfuscated function
    """
    addr = start
    erg = 0
    counter = 0
    while addr <= end:
        a = DfirstB(addr)
        if (a != BADADDR):
            counter += 1
            erg = addr
        addr += 1
    if counter != 1:
        print 'could not resolve start_addr'
        return BADADDR
    else:
        return erg


# Badaddr is set from Ida, so i can use this
def set_dissassembly_type():
    """
    @brief Determines if disassembly is 32 or 64 bitdeobfuscate
    """
    if BADADDR == 0xffffffffffffffff:
        SV.dissassm_type = SV.ASSEMBLER_64
    else:
        SV.dissassm_type = SV.ASSEMBLER_32


def get_jaddr_from_comments(pp_lst, comment_lst):
    """
    @brief reads in jump addresses wich were set by the
    reverse engineer
    
    @param pp_lst List of PseudoInstructions in push/pop represtentation
    @param comment_lst List of comments
    @return List of tuples (set jump address, address of jump instruction)
    """
    ret = []
    for comment, caddr in comment_lst:
        if 'jumps to: ' in comment:
            index = comment.find('jumps to: 0x')
            if index == -1:
                continue
            jmps = comment[index:len(comment)]
            index = jmps.find('0x')
            if index == -1:
                continue
            jmps = jmps[index:len(jmps)]
            str_lst = jmps.split(', ')
            for sub_str in str_lst:
                ret.append((long(sub_str, 16), caddr))
        else:
            continue
    return ret


def get_jmp_input_found(cjmp_addrs, jmp_addrs):
    """
    @brief Cobines the automatic found jump addresses
    with those from the reverse engineer
    
    @remark those addresses which were entered have preference
    @param cjmp_addrs Addresses form the reverse engineer
    @param jmp_addrs Automatic found addresses
    @return List of tuples (jump address, address of jump instruction)
    """
    ejmp_addrs = []
    ejmp_addrs += cjmp_addrs
    for (jaddr, inst_addr) in jmp_addrs:
        found = False
        for _, cinst_addr in cjmp_addrs:
            if cinst_addr == inst_addr:
                found = True
        if not found:
            ejmp_addrs.append((jaddr, inst_addr))
    return ejmp_addrs


def change_comments(pp_lst, cjmp_addrs):
    """
    @brief Sets the entered jump addresses in the comments
    of the PseudoInstructions
    
    @param pp_lst  List of PseudoInstructions in push/pop represtentation
    @param cjmp_addrs List of tuples (set jump address,
    address of jump instruction)
    """
    for item in pp_lst:
        if item.inst_type == PI.JMP_T:
            found_vals = []
            for jaddr, inst_addr in cjmp_addrs:
                if inst_addr == item.addr:
                    found_vals.append(jaddr)
            if len(found_vals) == 0:
                continue
            comment = 'jumps to: '
            found_addr = False
            for addr in found_vals:
                comment += '{0:#x}, '.format(addr)
            comment = comment[:len(comment) - 2]
            item.comment = comment


def get_jmp_addr(bb):
    """
    @param bb List of PseudoInstructions of one basic block
    @return Address of jump instruction in this basic block
    """
    for inst in bb:
        if inst.inst_type == PI.JMP_T:
            return inst.addr
    return None


def has_ret(bb):
    """
    @param bb List of PseudoInstructions of one basic block
    @return True if ret instruction is part of basic block, False otherwise
    """
    return (lambda bb: True if 'ret_T' in map(lambda inst: inst.inst_type, bb) else False)(bb)

def get_jmp_loc(jmp_addr, jmp_addrs):
    """
    @param jmp_addr Address of jmp instruction
    @param jmp_addrs List of Tuples (jump address, address of jmp instruction)
    @return A list of all addresses a jmp instruction can jump to
    """
    return [jmp_to for jmp_to, j_addr in jmp_addrs if j_addr == jmp_addr]


def deobfuscate(code_saddr,  base_addr, code_eaddr, vm_addr, display=4, real_start=0):
    """
    @brief This function does the deobfuscation between code_saddr and code_eaddr
    @param code_saddr Address of the start of obfuscated code
    @param base_addr Address of the jumptable of the virtual machine
    @param code_eaddr Address of the end of obfuscated code
    @param vm_addr Address of the virtual machine function
    @param display Set output type
        * 0 : VirtualInstruction
        * 1 : PseudoInstruction Push/Pop representation
        * 2 : PseudoInstruction full optimized
    @param real_start Address of entry point of the function
    @return The lowest found jump address
    """
    set_dissassembly_type()
    comment_list = read_in_comments(code_saddr, code_eaddr)
    if real_start == 0:
        start_addr = find_start(code_saddr, code_eaddr)
    else:
        start_addr = real_start
    if start_addr == BADADDR:
        start_addr = code_saddr
    f_start_lst = []
    if vm_addr != 0:
        f_start_lst = get_start_push(vm_addr)
        f_start_lst = to_vpush(f_start_lst, start_addr)
    vm_inst_lst = first_deobfuscate(code_saddr, base_addr, code_eaddr)
    vm_inst_lst1 = deobfuscate_all(base_addr)
    display_vm_inst(vm_inst_lst1)
    pseudo_lst = add_ret_pop(vm_inst_lst)
    push_pop_lst = []
    lst = []
    for inst in pseudo_lst:
        if inst.addr == start_addr:
            lst = f_start_lst
        lst += inst.make_pop_push_rep()
        for rep in lst:
            push_pop_lst.append(rep)
        lst = []
    cjmp_addrs = get_jaddr_from_comments(push_pop_lst, comment_list)
    jmp_addrs = get_jmp_addresses(push_pop_lst, code_eaddr)
    jmp_addrs = get_jmp_input_found(cjmp_addrs, jmp_addrs)
    change_comments(push_pop_lst, cjmp_addrs)
    basic_blocks = find_basic_blocks(push_pop_lst, start_addr, jmp_addrs)
    if basic_blocks == None:
        basic_blocks = [(code_saddr, code_eaddr)]
    color_basic_blocks(basic_blocks)
    basic_lst = make_bb_lists(push_pop_lst, basic_blocks)
    has_loc = has_locals(basic_lst)
    clear_comments(code_saddr, code_eaddr)
    if display == 0:
        vm_list = f_start_lst + pseudo_lst
        display_vm_inst(vm_list)
    elif display == 1:
        display_ps_inst(push_pop_lst)
    else:
        opt_basic = []
        display_lst = []
        nodes = []
        edges = []
        for lst in basic_lst:
            opt_lst = optimize(lst, has_loc)
            display_lst += opt_lst
            opt_basic.append(opt_lst)
        display_ps_inst(display_lst)
        for node, bb in enumerate(opt_basic):
            if bb == []:
                continue
            nodes.append(('bb%d' % (node)))

            if has_ret(bb):
                continue

            jmp_addr = get_jmp_addr(bb)
            if jmp_addr == None:
                edges.append(('bb%d' % (node), 'bb%d' % (node + 1)))
            else:
                jmp_locs = get_jmp_loc(jmp_addr, jmp_addrs)
                for loc in jmp_locs:
                    for pos, (saddr, eaddr) in enumerate(basic_blocks):
                        if loc >= saddr and loc < eaddr:
                            edges.append(('bb%d' % (node), 'bb%d' % (pos)))
        try:
            g = show_graph(nodes, edges, opt_basic, jmp_addrs, basic_blocks, real_start)
        except Exception, e:
            print e.message
    if jmp_addrs != []:
        min_jmp = min(jmp_addrs)[0]
    else:
        min_jmp = BADADDR
    return min_jmp


# need this to auto delete all variables
# so there are no objects left in ida python shell
# TODO
# * problem mit x64 push/pop
# * vebpmov Problem?
# * evtl schreibe start push to comments
def start(code_saddr, base_addr, code_eaddr, vm_addr, display=4, real_start=0):
    """
    @brief Entrypoint of the deobfuscation; starts
    deobfuscate until the minimal code start address is found
    @param code_saddr Address of the start of obfuscated code
    @param base_addr Address of the jumptable of the virtual machine
    @param code_eaddr Address of the end of obfuscated code
    @param vm_addr Address of the virtual machine function
    @param display Set output type
        * 0 : VirtualInstruction
        * 1 : PseudoInstruction Push/Pop representation
        * 2 : PseudoInstruction full optimized
    @param real_start Address of entry point of the function
    """
    old_min = BADADDR
    n_min = code_saddr
    start = real_start
    while old_min > n_min:
        old_min = n_min
        n_min = deobfuscate(old_min, base_addr, code_eaddr, vm_addr, display, start)
        if start == 0:
            start = code_saddr
            # if n_min < 0x4048b6:# TODO
            #    break

def color_basic_blocks(basic_lst):
    """
    @brief Colors the basic blocks
    @param basic_lst List of Tuples: (address start basic block,
    address end basic block)
    """
    color = 0
    for start, end in basic_lst:
        if (start + 1 == end):
            continue
        pos = start
        while pos < end:
            SetColor(pos, CIC_ITEM, bb_colors[color % len(bb_colors)])
            pos += 1
        color += 1


def make_bb_lists(pp_lst, basic_lst):
    """
    @brief Generates basic blocks and returns them in a list
    @param pp_lst  List of PseudoInstructions in push/pop represtentation
    @param basic_lst List of Tuples: (address start basic block,
    address end basic block)
    @return List of basic block lists
    """
    bb_lists = []
    for (s_addr, e_addr) in basic_lst:
        bb_lst = []
        for inst in pp_lst:
            if inst.addr >= s_addr and inst.addr < e_addr:
                bb_lst.append(inst)
        bb_lists.append(bb_lst)
    return bb_lists


def has_locals(bb_lsts):
    """
    @brief Determines if the function reserves space for local variables
    @param List of basic blocks
    @return True if function has locals, False otherwise
    """
    has_ebp_mov = False
    for bb in bb_lsts:
        has_ebp_mov = False
        for inst in bb:
            if inst.inst_type == PI.MOV_EBP_T:
                has_ebp_mov = True
            if inst.inst_type == PI.RET_T and has_ebp_mov:
                return True
    return False


def print_bb(bb_lsts):
    """
    @brief Print start and end of basic block; is used for debugging
    @param bb_lsts List of basic block lists
    """
    block_count = 1
    for lst in bb_lsts:
        print 'Start BB', block_count
        for inst in lst:
            print str(inst)[:len(str(inst)) - 1]
        print 'End BB', block_count
        block_count += 1


def get_distorm_info(inst_addr):
    """
    @brief Prints whole distrom3 info of the given instruction
    @param inst_addr Address of instruction
    """
    size = ItemSize(inst_addr)
    inst_bytes = GetManyBytes(inst_addr, size)
    inst = distorm3.Decompose(inst_addr,
                              inst_bytes, distorm3.Decode64Bits, 0)
    print inst[0]
    i = inst[0]
    print 'InstBytes ', i.instructionBytes
    print 'Opcode ', i.opcode
    for o in i.operands:
        print 'operand ', o
        print 'operand type', o.type
    for f in i.flags:
        print 'flag ', f
        print 'raw_flags ', i.rawFlags
    print 'inst_class ', i.instructionClass
    print 'flow_control ', i.flowControl
    print 'address ', i.address
    print 'size ', i.size
    print 'dt ', i.dt
    print 'valid ', i.valid
    print 'segment ', i.segment
    print 'unused_Prefixes ', i.unusedPrefixesMask
    print 'mnemonic ', i.mnemonic
    print 'inst_class ', i.instructionClass


def jmp_to_orig(address, base):
    """
    @brief Jumps to the executed x86 code
    @param address Address of virtual code
    @param base Address of the jumptable of the virtual machine
    """
    if SV.dissassm_type == 64:
        Jump(Qword((Byte(address) * 8) + base))
    else:
        Jump(Dword((Byte(address) * 4) + base))

        ###########
        # outdated
        ###########

        # change bad prog style
        # def reg_to_value(instr_lst, reg, value):
        #    erg = []
        #    for item in instr_lst:
        #        if reg in item.Op1:
        #            item.Op1 = item.Op1.replace(reg, '{0:#x}'.format(value))
        #        if reg in item.Op2:
        #            item.Op2 = item.Op2.replace(reg, '{0:#x}'.format(value))
        #        erg.append(item)
        #    return erg

        # def remove_vm_inst(instr_lst):
        #    erg = []
        #    for item in instr_lst:
        #        if not item.is_vinst():
        #            erg.append(item)
        #    return erg

        # seems to work
        # def test_scretch_operand():
        #    t60 = PI.ScretchOperand(PI.SVARIABLE_T, 60, 4)
        #    t10 = PI.ScretchOperand(PI.SVARIABLE_T, 60, 4)
        #    t11 = PI.ScretchOperand(PI.SVARIABLE_T, 11, 4)
        #
        #    inst0 = PI.PseudoInstruction('vpop', 0, [t60], 4)
        #    inst1 = PI.PseudoInstruction('vpop', 0, [t10], 4)
        # inst1.op_lst[0].value = 0xcaffee
        # inst0.op_lst[0].value = 0xbabe5
        #    print inst1.op_lst[0].value
        #    print '{0:#x}'.format(inst1.op_lst[0].value)


def static_vmctx(manual=False):
    """
    Compute the VM context values statically.
    :param manual: Bool -> Print result to the console
    """
    vm_ctx = VMContext()
    vm_seg_start = None
    vm_seg_end = None
    prev = 0
    # try to find the vm Segment via name -> easiest case but also easy to foil
    for addr in Segments():
        if SegName(addr).startswith('.vmp'):
            vm_seg_start = SegStart(addr)
            vm_seg_end = SegEnd(addr)
            break
    for f in Functions(vm_seg_start, vm_seg_end):
        if (GetFunctionAttr(f, FUNCATTR_END) - GetFunctionAttr(f, FUNCATTR_START)) > prev:
            prev = GetFunctionAttr(f, FUNCATTR_END) - GetFunctionAttr(f, FUNCATTR_START)
            vm_addr = f

    base_addr = NextHead(vm_addr)
    while base_addr < vm_seg_end:
        if GetMnem(base_addr).startswith('jmp'):
            try:
                base_addr = int(re.findall(r'.*off_([0123456789abcdefABCDEF]*)\[.*\]', GetOpnd(base_addr, 0))[0], 16)
                break
            except Exception, e:
                print e.message
                print e.args
        else:
            base_addr = NextHead(base_addr)
    if base_addr > vm_seg_end:
        base_addr = AskAddr(base_addr, 'Could not determine the Startaddr of the jmp table, please specify: ')

    code_start = PrevAddr(vm_seg_end)
    while not GetDisasm(code_start).__contains__('jmp'):
        code_start = PrevAddr(code_start)
    code_end = vm_seg_end
    code_start += 1

    vm_ctx.code_start = code_start
    vm_ctx.code_end = code_end
    vm_ctx.base_addr = base_addr
    vm_ctx.vm_addr = vm_addr

    vmr = get_vmr()
    vmr.vm_ctx = vm_ctx

    if manual:
        print 'Code Start: %x; Code End: %x; Base Addr: %x; VM Addr: %x' % (code_start, code_end, base_addr, vm_addr)

def static_deobfuscate(display=0, userchoice=False):
    """
    Wrapper for deobfuscate function which allows for manual user Input.
    :param display: Bool -> use output window or BBGraphViewer
    :param userchoice: let user input vm context values
    """
    vmr = get_vmr()
    if vmr.code_start == BADADDR:
        try:
            vm_ctx = static_vmctx()
            vmr.vm_ctx = vm_ctx
        except Exception, e:
            print e.message
            print e.args
    if userchoice:
        code_start = AskAddr(vmr.code_start, 'Choose start of byte code:')
        code_end = AskAddr(vmr.code_end, 'Choose end of byte code:')
        base_addr = AskAddr(vmr.base_addr, 'Coose start of jmp table:')
        vm_addr = AskAddr(vmr.vm_addr, 'Choose start of the virtual machine function:')
        deobfuscate(code_start, base_addr, code_end, vm_addr, display)
    else:
        deobfuscate(vmr.code_start, vmr.base_addr, vmr.code_end, vmr.vm_addr, display)



