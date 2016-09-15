# coding=utf-8
__author__ = 'Anatoli Kalysch'

from ui.ClusterViewer import ClusterViewer
from copy import deepcopy
from _collections import deque
from dynamic.TraceRepresentation import Traceline, Trace
from lib.Register import get_reg_by_size
from lib.TraceAnalysis import repetition_clustering, find_virtual_regs, create_bb_diff
from lib.TraceOptimizations import optimizations, optimization_names, optimization_selective_register_folding
from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore
from ui.NotifyProgress import NotifyProgress


###########################
### Trace Optimizations ###
###########################
class OptimizationViewer(PluginViewer):
    def __init__(self, trace, title='Optimizations', **kwargs):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(OptimizationViewer, self).__init__(title)
        self.orig_trace = trace
        self.trace = deepcopy(trace)
        self.undo_stack = deque([deepcopy(trace), deepcopy(trace), deepcopy(trace)], maxlen=3)
        self.opti_map = dict(zip(optimization_names, optimizations))
        self.order = []
        self.foldable_regs = []
        self.save = kwargs.get('save', None)


    def PopulateModel(self, trace):
        self.CleanModel()

        w = NotifyProgress()
        w.show()
        ctr = 0
        max = len(trace)

        for line in trace:

            assert isinstance(line, Traceline)
            tid = QtGui.QStandardItem('%s' % line.thread_id)
            addr = QtGui.QStandardItem('%x' % line.addr)
            disasm = QtGui.QStandardItem(line.disasm_str())
            comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
            context = QtGui.QStandardItem(''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx.keys() if line.ctx is not None))

            ctr += 1
            w.pbar_set(int(float(ctr) / float(max) * 100))

            self.sim.appendRow([tid, addr, disasm, comment, context])

        w.close()

        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)
        self.treeView.resizeColumnToContents(3)
        self.treeView.resizeColumnToContents(4)

    def CleanModel(self):
        self.sim.clear()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

    def PopulateOptimizationsToolbar(self):
        self.ftb.addWidget(QtGui.QLabel('Available Optimizations (check to run on trace): '))
        self.cpcb = QtGui.QCheckBox(optimization_names[0])
        self.cpcb.stateChanged.connect(lambda: self.OptimizeTrace(self.cpcb))
        self.ftb.addWidget(self.cpcb)
        self.ftb.addSeparator()

        self.sacb = QtGui.QCheckBox(optimization_names[1])
        self.sacb.stateChanged.connect(lambda: self.OptimizeTrace(self.sacb))
        self.ftb.addWidget(self.sacb)
        self.ftb.addSeparator()

        self.oscb = QtGui.QCheckBox(optimization_names[2])
        self.oscb.stateChanged.connect(lambda: self.OptimizeTrace(self.oscb))
        self.ftb.addWidget(self.oscb)
        self.ftb.addSeparator()

        self.uocb = QtGui.QCheckBox(optimization_names[3])
        self.uocb.stateChanged.connect(lambda: self.OptimizeTrace(self.uocb))
        self.ftb.addWidget(self.uocb)
        self.ftb.addSeparator()

        self.pcb = QtGui.QCheckBox(optimization_names[4])
        self.pcb.stateChanged.connect(lambda: self.OptimizeTrace(self.pcb))
        self.ftb.addWidget(self.pcb)
        self.ftb.addSeparator()

    def PopulateSelectiveRegsToolbar(self):
        self.stb.addWidget(QtGui.QLabel('Selective Register Folding: '))
        assert isinstance(self.trace, Trace)
        if self.trace.ctx_reg_size == 32:
            for i in range(8):
                self.foldable_regs.append(QtGui.QCheckBox(get_reg_by_size(i, self.trace.ctx_reg_size)))
                self.foldable_regs[-1].stateChanged.connect(lambda: self.FoldRegs())
                self.stb.addWidget(self.foldable_regs[-1])
                self.stb.addSeparator()
        elif self.trace.ctx_reg_size == 64:
            for i in range(16):
                self.foldable_regs.append(QtGui.QCheckBox(get_reg_by_size(i, self.trace.ctx_reg_size)))
                self.foldable_regs[-1].stateChanged.connect(lambda: self.FoldRegs())
                self.stb.addWidget(self.foldable_regs[-1])
                self.stb.addSeparator()


    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

        # toolbar
        self.ftb = QtGui.QToolBar()
        self.stb = QtGui.QToolBar()

        # tree view
        self.treeView = QtGui.QTreeView()
        self.treeView.setToolTip('Filter instructions from trace by double clicking on them.')
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        # Context menus
        self.treeView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.treeView.customContextMenuRequested.connect(self.OnCustomContextMenu)

        self.treeView.doubleClicked.connect(self.ItemDoubleClickSlot)
        self.treeView.setModel(self.sim)

        ### populate widgets
        # fill model with data
        self.PopulateModel(self.orig_trace)
        # fill toolbars with data
        self.PopulateOptimizationsToolbar()
        self.PopulateSelectiveRegsToolbar()
        # finalize layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.ftb)
        layout.addWidget(self.stb)
        layout.addWidget(self.treeView)


        self.parent.setLayout(layout)

    def OptimizeTrace(self, check_box):
        self.undo_stack.append(deepcopy(self.trace))
        self.last_cb = check_box
        optimization = self.opti_map[check_box.text()]
        if check_box.isChecked():
            self.order.append(optimization)
            self.trace = optimization(self.trace)
        else:
            try:
                self.order.remove(optimization)
            except:
                pass
            self.trace = deepcopy(self.orig_trace)
            for optimization in self.order:
                self.trace = optimization(self.trace)
        self.FoldRegs()

    def FoldRegs(self):
        self.undo_stack.append(deepcopy(self.trace))
        folded_regs = []
        for check_box in self.foldable_regs:
            if check_box.isChecked():
               folded_regs.append(check_box.text())
        self.trace = optimization_selective_register_folding(self.trace, folded_regs)

        self.PopulateModel(self.trace)

    def IsVisible(self):
        try:
            return self.treeView.isVisible()
        except:
            return False

    @QtCore.Slot(QtCore.QModelIndex)
    def ItemDoubleClickSlot(self, index):
        """
        TreeView DoubleClicked Slot.
        @param index: QModelIndex object of the clicked tree index item.
        @return:
        """
        # fetch the clicked string
        instr = index.data(0)
        # if instr is an instruction, remove trace lines with said instruction
        self.trace = Trace(tr=[line for line in self.trace if line.disasm_str() != instr])

        self.PopulateModel(self.trace)

    @QtCore.Slot(QtCore.QPoint)
    def OnCustomContextMenu(self, point):
        menu = QtGui.QMenu()
        # Actions
        action_undo = QtGui.QAction('Undo', self.treeView, triggered=lambda: self.Undo())
        action_restore = QtGui.QAction('Restore original trace', self.treeView, triggered=lambda: self.Restore())
        action_forward_to_clustering = QtGui.QAction("Open in Clustering Analysis", self.treeView, triggered=lambda: self.ClusterForward())
        action_export_trace = QtGui.QAction('Export this trace...', self.treeView, triggered=lambda: self.SaveTrace())
        action_close_viewer = QtGui.QAction('Close Viewer', self.treeView, triggered=lambda: self.Close(4))

        # add actions to menu
        menu.addAction(action_undo)
        menu.addAction(action_restore)
        menu.addAction(action_forward_to_clustering)
        menu.addAction(action_export_trace)
        menu.addSeparator()
        menu.addAction(action_close_viewer)

        menu.exec_(self.treeView.viewport().mapToGlobal(point))

    @QtCore.Slot(str)
    def ClusterForward(self):
        # cluster
        vr = find_virtual_regs(deepcopy(self.trace))
        cluster = repetition_clustering(deepcopy(self.trace))
        v0 = ClusterViewer(cluster, create_bb_diff, self.trace.ctx_reg_size)
        v0.Show()
        # Do not display StackChangeViewer. After the user worked on the trace it will be heavily malformed and missing crutial information for a stack change analysis, so the stack change view will do more harm than good.

    @QtCore.Slot(str)
    def SaveTrace(self):
        if self.save is not None:
            self.save(self.trace)

    @QtCore.Slot(str)
    def Undo(self):
        self.trace = self.undo_stack[-1]
        self.last_cb.setCheckState(QtCore.Qt.Unchecked)
        self.PopulateModel(self.trace)

    @QtCore.Slot(str)
    def Restore(self):
        self.undo_stack = [self.orig_trace]
        self.order = []
        self.cpcb.setCheckState(QtCore.Qt.Unchecked)
        self.sacb.setCheckState(QtCore.Qt.Unchecked)
        self.oscb.setCheckState(QtCore.Qt.Unchecked)
        self.uocb.setCheckState(QtCore.Qt.Unchecked)
        self.pcb.setCheckState(QtCore.Qt.Unchecked)
        try:
            for check_box in self.foldable_regs:
                check_box.setCheckState(QtCore.Qt.Unchecked)
        except:
            pass
        self.trace = deepcopy(self.orig_trace)
        self.PopulateModel(self.trace)
