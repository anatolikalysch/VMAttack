# coding=utf-8
from ui.NotifyProgress import NotifyProgress

__author__ = 'Anatoli Kalysch'

from dynamic.TraceRepresentation import Traceline
from idc import AskLong
from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore, QtWidgets
# from PyQt5 import QtGui, QtCore, QtWidgets


###########################
### GradingSys Analysis ###
###########################
class GradingViewer(PluginViewer):
    def __init__(self, trace, title='Grading System Analysis', **kwargs):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(GradingViewer, self).__init__(title)
        self.trace = trace
        self.save = kwargs.get('save', None)
        self.grades = kwargs.get('grades', None)
        if self.grades is None:
            self.grades = self.GetGrades()

    def GetGrades(self):
        return set([line.grade for line in self.trace])

    def PopulateModel(self, threshold):
        self.CleanModel()

        w = NotifyProgress()
        ctr = 0
        max = len(self.trace)
        prev = None
        for line in self.trace:
            assert isinstance(line, Traceline)

            if prev is not None and threshold > 2:
                if prev is not None:
                    grade = QtGui.QStandardItem(' ')
                    tid = QtGui.QStandardItem(' ')
                    addr = QtGui.QStandardItem(' ')
                    disasm = QtGui.QStandardItem('previous CPU context:')
                    comment = QtGui.QStandardItem(' ')
                    context = QtGui.QStandardItem(''.join('%s:%s ' % (c, prev.ctx[c]) for c in prev.ctx.keys() if prev.ctx is not None))
                    self.sim.appendRow([grade, tid, addr, disasm, comment, context])
                grade = QtGui.QStandardItem('%s' % line.grade)
                tid = QtGui.QStandardItem('%s' % line.thread_id)
                addr = QtGui.QStandardItem('%x' % line.addr)
                disasm = QtGui.QStandardItem(line.disasm_str())
                comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
                context = QtGui.QStandardItem(''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx.keys() if line.ctx is not None))

                self.sim.appendRow([grade, tid, addr, disasm, comment, context])

            ctr += 1
            w.pbar_set(int(float(ctr) / float(max) * 100))
            prev = line
        w.close()

        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)
        self.treeView.resizeColumnToContents(3)
        self.treeView.resizeColumnToContents(4)
        self.treeView.resizeColumnToContents(5)

    def CleanModel(self):
        self.sim.clear()
        self.sim.setHorizontalHeaderLabels(['Grade','ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])


    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

        # toolbar
        self.ftb = QtWidgets.QToolBar()
        self.stb = QtWidgets.QToolBar()

        # tree view
        self.treeView = QtWidgets.QTreeView()
        self.treeView.setToolTip('Double click a grade to filter')
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        # Context menus
        self.treeView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.treeView.customContextMenuRequested.connect(self.OnCustomContextMenu)

        self.treeView.doubleClicked.connect(self.ItemDoubleClickSlot)
        self.treeView.setModel(self.sim)

        ### populate widgets
        # fill model with data
        self.PopulateModel(0)
        # finalize layout
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.treeView)


        self.parent.setLayout(layout)


    def IsVisible(self):
        try:
            return self.treeView.isVisible()
        except:
            return False

    @QtCore.pyqtSlot(QtCore.QModelIndex)
    def ItemDoubleClickSlot(self, index):
        """
        TreeView DoubleClicked Slot.
        @param index: QModelIndex object of the clicked tree index item.
        @return:
        """
        # fetch the clicked string
        try:
            instr = int(index.data(0))
        except:
            instr = None
        if instr in self.grades:
            # if instr is an instruction, remove trace lines with said instruction
            self.PopulateModel(instr)


    @QtCore.pyqtSlot(QtCore.QPoint)
    def OnCustomContextMenu(self, point):
        menu = QtWidgets.QMenu()

        # Actions
        action_set_t = QtWidgets.QAction('Set grade threshold...', self.treeView)
        action_set_t.triggered.connect(self.SetThreshold)
        action_restore = QtWidgets.QAction('Show All', self.treeView)
        action_restore.triggered.connect(self.Restore)
        action_export_trace = QtWidgets.QAction('Export this trace...', self.treeView)
        action_export_trace.triggered.connect(self.SaveTrace)
        action_close_viewer = QtWidgets.QAction('Close Viewer', self.treeView)
        action_close_viewer.triggered.connect(lambda: self.Close(4))
        # add actions to menu
        menu.addAction(action_set_t)
        menu.addAction(action_restore)
        menu.addAction(action_export_trace)
        menu.addSeparator()
        menu.addAction(action_close_viewer)

        menu.exec_(self.treeView.viewport().mapToGlobal(point))

    @QtCore.pyqtSlot(str)
    def SetThreshold(self):
        threshold = AskLong(-1, 'There are a total of %s grades: %s. Specify a threshold which lines to display:' % (len(self.grades), ''.join('%s ' % c for c in self.grades)))
        if threshold in self.grades:
            self.PopulateModel(threshold)


    @QtCore.pyqtSlot(str)
    def SaveTrace(self):
        if self.save is not None:
            self.save(self.trace)

    @QtCore.pyqtSlot(str)
    def Restore(self):
        self.PopulateModel(0)