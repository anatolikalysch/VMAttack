# coding=utf-8
from lib.Logging import get_log

__author__ = 'Anatoli Kalysch'

import ui.SettingsWindow as SettingsWindow
from dynamic.dynamic_deobfuscate import *
from lib.VMRepresentation import *
from static.static_deobfuscate import *
from ui.AboutWindow import AboutWindow
from ui.UIManager import UIManager


class VMAttack_Manager(object):
    def __init__(self):
        self.choice = None
        self._vmr = get_vmr()

        # UI Management
        self.ui_mgr = UIManager()
        self.ui_mgr.get_init_menu()
        self.menu_name = "VMAttack"
        self.menu_extensions = []

    ### EVIRONMENT AND INIT ###
    @property
    def trace(self):
        return self.vmr._trace

    @trace.setter
    def trace(self, value):
        self.vmr._trace = value

    @property
    def vmr(self):
        self.update_vmr()
        return self._vmr

    @property
    def dbg_handl(self):
        return get_dh(self.choice)

    @dbg_handl.setter
    def dbg_handl(self, value):
        self.vmr._dbg_handl = value

    @property
    def vm_operands(self):
        return self.vmr._vm_operands

    @vm_operands.setter
    def vm_operands(self, value):
        self.vmr._vm_operands = value

    @property
    def vm_returns(self):
        return self.vmr._vm_returns

    @vm_returns.setter
    def vm_returns(self, value):
        self.vmr._vm_returns = value

    @property
    def vm_ctx(self):
        return self.vmr._vm_ctx

    @vm_ctx.setter
    def vm_ctx(self, value):
        self.vmr._vm_ctx = value

    def select_debugger(self):
        c = Choose([], "Choose your preferred debugger:", 1)
        c.list = ["Currently selected IDA Debugger", "Bochs Dbg", "Win32 Dbg"]  # TODO , "OllyDbg", "Immunity Dbg"]
        c.width = 33
        # choose() starts counting at 1, not 0
        self.choice = c.choose() - 1
        if self.choice == 1:
            LoadDebugger('Bochs', 0)
        elif self.choice == 2:
            LoadDebugger('Win32', 0)

    def update_vmr(self):
        self._vmr = get_vmr()

    ### UI MANAGEMENT ###
    @staticmethod
    def show_about():
        AboutWindow().exec_()

    @staticmethod
    def show_settings():
        SettingsWindow.Show()

    def show_trace(self):
        self.update_vmr()
        if self._vmr.trace is not None:
            for line in self._vmr.trace:
                print line.to_str_line()

    def remove_colors(self):
        # reset color
        heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
        for i in heads:
            SetColor(i, CIC_ITEM, 0xFFFFFF)

    def extend_menu(self):
        """
        Extends the menu.
        """
        try:
            self.revert_menu()
            menu_path = self.menu_name + "/"
            self.ui_mgr.get_init_menu()
            self.ui_mgr.add_menu('&'+self.menu_name)

            # debugger selection - will be added after plugin interaction with ollydbg and immunitydbg will be enabled - as of now no additional value is generated compared to the debugger selection in IDA itself so it is commented out
            # An alternative to the chooser would be to hook IDAs Debugger selection?
            #select_debugger_menu_item = add_menu_item(menu_path, "Select VMAttack Debugger", "", 0, self.select_debugger, None)
            # credits & settings
            settings_menu_item = add_menu_item(menu_path, "Settings", "", 0, self.show_settings, None)
            about_menu_item = add_menu_item(menu_path, "About ...", "", 0, self.show_about, None)
            # instruction trace generation and handling
            remove_colors_menu_item = add_menu_item(menu_path + "Instruction Trace/", "Remove Colors from Graph", "", 0, self.remove_colors, None)
            load_trace_menu_item = add_menu_item(menu_path + "Instruction Trace/", "Load Trace", "", 0, load_trace, None)
            save_trace_menu_item = add_menu_item(menu_path + "Instruction Trace/", "Save Trace", "", 0, save_trace, None)
            gen_trace_menu_item = add_menu_item(menu_path + "Instruction Trace/", "Generate Trace", "", 0, gen_instruction_trace, (self.choice,))
            show_trace_menu_item = add_menu_item(menu_path + "Instruction Trace/", "Show Trace", "", 0, self.show_trace, None)



            ### automation ###
            grading_menu_item = add_menu_item(menu_path + 'Automated Analysis/', "Grading System Analysis", "", 0, grading_automaton, None)
            automaton_menu_item = add_menu_item(menu_path + 'Automated Analysis/', "Run all analysis capabilities", "", 0, self.automaton, None)

            show_opti_menu_item = add_menu_item(menu_path + "Automated Analysis/Semi Automated (dynamic)/", "Dynamic Trace Optimization", "", 0, optimization_analysis, None)
            analyze_addr_trace_menu_item = add_menu_item(menu_path + 'Automated Analysis/Semi Automated (dynamic)/', "Clustering Analysis", "", 0, clustering_analysis, None)
            show_input_output = add_menu_item(menu_path + "Automated Analysis/Semi Automated (dynamic)/", "VM Input<=>Ouput Analysis", "", 0, input_output_analysis, None)

            deobfuscate_from_menu_item = add_menu_item(menu_path + "Automated Analysis/Semi Automated (static)/", "Static deobfuscate", "", 0, static_deobfuscate, None)
            show_abstract_graph_menu_item = add_menu_item(menu_path + "Automated Analysis/Semi Automated (static)/", "Create Abstract VM-Graph", "", 0, static_deobfuscate, (2,))
            ### manual analysis ###
            # vm context related
            static_start_search_menu_item = add_menu_item(menu_path + "Manual Analysis/VM Context/", "Find VM Context (static)", "", 0, static_vmctx, (True,))
            find_vm_values_menu_item = add_menu_item(menu_path + "Manual Analysis/VM Context/", "Find VM Context (dynamic)", "", 0, dynamic_vmctx, (True,))
            # static analysis menu items
            manual_static_menu_item = add_menu_item(menu_path + "Manual Analysis/Static/", "Deobfuscate from ...", "", 0, static_deobfuscate, (0,True))
            # dynamic analysis menu items
            follow_virt_register = add_menu_item(menu_path + "Manual Analysis/Dynamic/", "Follow Virtual Register", "", 0, manual_analysis, (3,))
            find_reg_mapping = add_menu_item(menu_path + "Manual Analysis/Dynamic/", "Find Virtual Reg to Reg mapping", "", 0, manual_analysis, (2,))
            find_vmfunc_input = add_menu_item(menu_path + "Manual Analysis/Dynamic/", "Find VM Function Input Parameter", "", 0, manual_analysis, (1,))
            find_vmfunc_output = add_menu_item(menu_path + "Manual Analysis/Dynamic/", "Find VM Function Output Parameter", "", 0, manual_analysis, (0,))
            analyze_count_menu_item = add_menu_item(menu_path + "Manual Analysis/Dynamic/", "Address Count", "", 0, address_heuristic, None)
            #manual_input_output = add_menu_item(menu_path + "Manual Analysis/Dynamic/", " Run Input<=>Ouput Analysis on Function", "", 0, input_output_analysis, (True,))


            self.menu_extensions.append(deobfuscate_from_menu_item)
            self.menu_extensions.append(settings_menu_item)
            #self.menu_extensions.append(select_debugger_menu_item)
            self.menu_extensions.append(load_trace_menu_item)
            self.menu_extensions.append(save_trace_menu_item)
            self.menu_extensions.append(gen_trace_menu_item)
            self.menu_extensions.append(analyze_count_menu_item)
            self.menu_extensions.append(analyze_addr_trace_menu_item)
            self.menu_extensions.append(static_start_search_menu_item)
            self.menu_extensions.append(find_vm_values_menu_item)
            self.menu_extensions.append(automaton_menu_item)
            self.menu_extensions.append(show_abstract_graph_menu_item)
            self.menu_extensions.append(find_vmfunc_input)
            self.menu_extensions.append(find_vmfunc_output)
            self.menu_extensions.append(manual_static_menu_item)
            self.menu_extensions.append(find_reg_mapping)
            self.menu_extensions.append(follow_virt_register)
            self.menu_extensions.append(show_input_output)
            self.menu_extensions.append(show_trace_menu_item)
            self.menu_extensions.append(about_menu_item)
            self.menu_extensions.append(show_opti_menu_item)
            self.menu_extensions.append(grading_menu_item)
            #self.menu_extensions.append(manual_input_output)
            self.menu_extensions.append(remove_colors_menu_item)


        except Exception, e:
            print "[*] Menu could not be added! Following Error occurred:\n %s" % e.message

    def revert_menu(self):
        for i in self.menu_extensions:
            del_menu_item(i)
        self.ui_mgr.clear()

    def welcome(self):
        msg("\n\
    ..........llllllllllllllllll..llllllll......llllll.......llllll..........\n\
    ..........llllllllllllllllll..lllllllll.....llllll.......llllll..........\n\
    ..........llllll.............lllll.lllll....llllll.......llllll..........\n\
    ..........llllll............,lllll.lllll,...llllll.......llllll..........\n\
    ..........llllll............llllll.llllll...llllll.......llllll..........\n\
    ..........lllllllllllllllllllllll...lllll...llllll.......llllll..........\n\
    ..........lllllllllllllllllllllll...llllll..llllll.......llllll..........\n\
    ..........llllllllllllllllllllll.....lllll..llllll.......llllll..........\n\
    ..........llllll..........lllllllllllllllll.llllll.......llllll..........\n\
    ..........llllll.........llllllllllllllllll.llllll.......llllll..........\n\
    ..........llllll........lllllllllllllllllllllllllll......llllll..........\n\
    ..........llllll........llllll.........lllllllllllllllllllllll...........\n\
    ..........llllll.......lllllll.........lllllll.lllllllllllll.............\n\
    ..........llllll......lllllll...........lllllll.lllllllllll..............\n\
    ............Friedrich-Alexander University Erlangen-Nuremberg............\n\
    ")

    def reset_grade(self, trace):
        for line in trace:
            line.grade = 0

        return trace

    def grade(self, trace, excerpt):
        for line in excerpt:
            trace[trace.index(line)].raise_grade()

        return trace

    # automaton
    def automaton(self):
        trace = prepare_trace()
        self.reset_grade(trace)
        # load current IDA-Debugger
        if self.dbg_handl.dbg.module_name is "NoDbg":
            self.dbg_handl = self.select_debugger()

        # instruction trace
        if trace is None:
            try:
                trace = self.dbg_handl.gen_instruction_trace()
            except:
                self._vmr.trace = prepare_trace()
        # run all trace analysis functions and present the results
        dynamic_vmctx()

        # afterwards if the VM context was found run the static analysis automatically since it depends on the VM context
        try:
            self.update_vmr()
            deobfuscate(self._vmr.code_start, self._vmr.base_addr, self._vmr.code_end, self._vmr.vm_addr)
        except Exception, e:
            try:
                static_vmctx()
                self.update_vmr()
                deobfuscate(self._vmr.code_start, self._vmr.base_addr, self._vmr.code_end, self._vmr.vm_addr)
            except Exception, ex:
                get_log().log('[AUT] Could not use static doubfuscation analysis due to the following error\n%s\n%s\n' % (e.message, ex.message))
                msg("[*] Could not provide static deobfuscation analysis! The following errors occured:\n %s \n %s" % (
                e.message, ex.message))


        # run the dynamic analysis capabilities of the plugin -> each analysis increases a special trace lines grade which will be evaluated at the end of the analysis
        # input / output
        try:
            input_output_analysis()
        except Exception, e:
            print '[*] Exception occured while running Input/Output analysis!\n %s' % e.message
        # clustering
        try:
            clustering_analysis()
        except Exception, e:
            print '[*] Exception occured while running Clustering analysis!\n %s' % e.message
        # optimizations
        try:
            optimization_analysis()
        except Exception, e:
            print '[*] Exception occured while running optimization analysis!\n %s' % e.message
        # grade the trace line
        try:
            grading_automaton()
        except Exception, e:
            print '[*] Exception occured while running grading analysis!\n %s' % e.message


# Virtualization obfuscated interpretation
class VMAttack(plugin_t):
    flags = PLUGIN_PROC
    comment = "This Framework is supposed to help with the analysis of virtualization obfuscated binaries."
    help = "HELP!"
    wanted_name = "VMAttack"
    wanted_hotkey = ""

    def init(self):
        self.vma_mgr = None
        try:
            self.vma_mgr = get_mgr()
            self.vma_mgr.extend_menu()
            #self.vma_mgr.welcome()
            msg('[*] Starting VMAttack plugin...\n')
            get_log().log('[VMA] Starting VMAttack and initiating variables ...\n')
            return PLUGIN_KEEP

        except Exception, e:
            msg("[*] Failed to initialize VMAttack.\n %s\n" % e.message)
            if self.vma_mgr is not None:
                self.vma_mgr.revert_menu()
                del self.vma_mgr
            return PLUGIN_SKIP

    def run(self, arg):
        try:
            self.vma_mgr = get_mgr()
            self.vma_mgr.extend_menu()
            #self.vma_mgr.welcome()
            msg('[*] Reloading VMAttack plugin...\n')
            add_menu_item('Edit/Plugins/', 'Load VMAttack', None, 0, self.vma_mgr.extend_menu, ())
        except Exception,e:
            msg("[*] Failed to initialize VMAttack.\n %s\n" % e.message)
            msg(e.args)

    def term(self):
        if self.vma_mgr is not None:
            get_log().finalize()
            self.vma_mgr.revert_menu()
            del_vmr()
            del self

def PLUGIN_ENTRY():
    return VMAttack()


# Singelton VMA MGR
vma_mgr = None

def get_mgr():
    global vma_mgr
    if vma_mgr is None:
        vma_mgr = VMAttack_Manager()
    return vma_mgr
