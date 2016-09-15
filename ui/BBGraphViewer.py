# coding=utf-8
__author__ = 'Anatoli Kalysch'

from idaapi import *
from idc import *
from lib.Instruction import Instruction


class GraphCloser(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph


    def activate(self, ctx):
        self.graph.Close()


    def update(self, ctx):
        return AST_ENABLE_ALWAYS


# class ColorChanger(action_handler_t):
#     def __init__(self, graph):
#         action_handler_t.__init__(self)
#         self.graph = graph
#
#
#     def activate(self, ctx):
#         self.graph.color = self.graph.color ^ 0xfffff0
#         self.graph.Refresh()
#         return 1
#
#
#     def update(self, ctx):
#         return AST_ENABLE_ALWAYS


def get_jmp_addr(bb):
    """
    @param bb List of PseudoInstructions of one basic block
    @return Address of jump instruction in this basic block
    """

    for inst in bb:
        if inst.inst_type == 'jmp_T':
            return inst.addr
    return None


class CallbackExtension(action_handler_t):
    def __init__(self, graph, bb_lst, jmp_addrs, basic_blocks, func_addr):
        action_handler_t.__init__(self)
        self.graph = graph
        self.bb_lst = bb_lst
        self.jmp_addrs = jmp_addrs
        self.basic_blocks = basic_blocks
        self.func_addr = func_addr

    def write_dot_rep(self, bb_lst, jmp_addrs, basic_blocks, func_addr):
        """
        @brief Write dot graph representation of obfuscated function
        @param bb_lst List of basic block lists
        @param jmp_addrs List of Tuples (jump address, address of jmp instruction)
        @param basic_blocks List of Tuples: (address start basic block,
        address end basic block)
        @param func_addr Addresse of the deobfuscated function
        """
        file_name = GetInputFile()
        char_num = file_name.find('.')
        file1 = open(file_name[:char_num] + '{0:#x}_dot'.format(func_addr), 'w')
        file1.write('digraph G {\n')
        file1.write('node [shape=box fontname=Courier];\n')
        depend = ''
        for node, bb in enumerate(bb_lst):
            if bb == []:
                continue
            label = ''
            for item in bb:
                label += ('{0:#x}    '.format(item.addr) +
                          str(item)[:len(str(item)) - 1] +
                          '    ' + item.comment + '\l')
            file1.write('bb' + str(node) +
                        ' [label=\"' + label + '\", style=filled, color=\"#' +
                        '{0:#x}'.format([0xddddff, 0xffdddd, 0xddffdd, 0xffddff, 0xffffdd, 0xddffff][node % 3])[2:] + '\"]\n')
            # check whether basic block has a ret instruction
            if (lambda bb: True if 'ret_T' in map(lambda inst: inst.inst_type, bb) else False)(bb):
                continue
            jmp_addr = get_jmp_addr(bb)
            if jmp_addr == None:
                depend += 'bb' + str(node) + '-> bb' + str(node + 1) + ';\n'
            else:
                jmp_locs = [jmp_to for jmp_to, j_addr in jmp_addrs if j_addr == jmp_addr]
                for loc in jmp_locs:
                    for pos, (saddr, eaddr) in enumerate(basic_blocks):
                        if loc >= saddr and loc < eaddr:
                            depend += ('bb' + str(node) +
                                       '-> bb' + str(pos) + ';\n')
        file1.write(depend)
        file1.write('}')
        file1.close()

    def activate(self, ctx):
        self.write_dot_rep(self.bb_lst, self.jmp_addrs, self.basic_blocks, self.func_addr)
        return 1


    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class BBGraph(GraphViewer):
    def __init__(self, n, e, bb_lst, jmp_addrs, basic_blocks, func_addr):
        self.title = "Absract VMFunctions Structure"
        GraphViewer.__init__(self, self.title)
        self.n = n
        self.e = e
        self.n_dict = {}
        self.bb_lst = bb_lst
        self.jmp_addrs = jmp_addrs
        self.basic_blocks = basic_blocks
        self.func_addr = func_addr
        for inst in bb_lst:
            if isinstance(inst, Instruction):
                print inst.__str__()

    def OnRefresh(self):
        self.Clear()
        run_var = 0
        for start, end in self.basic_blocks:
            self.n_dict[run_var] = self.AddNode(self.CreateNode(start, end))
            run_var += 1
        for tupel in self.e:
            self.AddEdge(self.n_dict[tupel[0]], self.n_dict[tupel[1]])

        return True


    def OnGetText(self, node_id):
        return str(self[node_id])


    def Show(self):
        GraphViewer.Show(self)
        # graph closer
        actname = "graph_closer:%s" % self.title
        register_action(action_desc_t(actname, "Close: %s" % self.title, GraphCloser(self)))
        attach_action_to_popup(self.GetTCustomControl(), None, actname)

        # # color changer
        # actname = "color_changer:%s" % self.title
        # register_action(action_desc_t(actname, "Change colors: %s" % self.title, ColorChanger(self)))
        # attach_action_to_popup(self.GetTCustomControl(), None, actname)

        # export graph to dot file
        actname = "export_dot_file:%s" % self.title
        register_action(action_desc_t(actname, "Export as dot file: %s" % self.title, CallbackExtension(self, self.bb_lst, self.jmp_addrs, self.basic_blocks, self.func_addr)))
        attach_action_to_popup(self.GetTCustomControl(), None, actname)

        return True

    def CreateNode(self, start, end):
        return ''.join('%s\n' % comment.rstrip('\t\n') for comment in filter(None, [Comment(addr) for addr in [ea for ea in xrange(start, end, 1)]]))


def show_graph(n, e, bb_lst, jmp_addrs, basic_blocks, func_addr):
    g = BBGraph(n, e, bb_lst, jmp_addrs, basic_blocks, func_addr)
    if g.Show():
        return g
    else:
        return None