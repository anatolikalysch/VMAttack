# coding=utf-8
from ui.NotifyProgress import NotifyProgress

__author__ = 'Anatoli Kalysch'


import os
import json
import time

from idaapi import get_root_filename

from dynamic.TraceRepresentation import Traceline
from idc import AskLong
from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore


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

        for line in self.trace:
            assert isinstance(line, Traceline)
            if line.grade >= threshold:
                grade = QtGui.QStandardItem('%s' % line.grade)
                tid = QtGui.QStandardItem('%s' % line.thread_id)
                addr = QtGui.QStandardItem('%x' % line.addr)
                disasm = QtGui.QStandardItem(line.disasm_str())
                comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
                context = QtGui.QStandardItem(''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx.keys() if line.ctx is not None))

                self.sim.appendRow([grade, tid, addr, disasm, comment, context])

            ctr += 1
            w.pbar_set(int(float(ctr) / float(max) * 100))
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
        self.ftb = QtGui.QToolBar()
        self.stb = QtGui.QToolBar()

        # tree view
        self.treeView = QtGui.QTreeView()
        self.treeView.setToolTip('Double click a grade to filter')
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
        self.PopulateModel(0)
        # finalize layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.treeView)


        self.parent.setLayout(layout)


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
        try:
            instr = int(index.data(0))
        except:
            instr = None
        if instr in self.grades:
            # if instr is an instruction, remove trace lines with said instruction
            self.PopulateModel(instr)


    @QtCore.Slot(QtCore.QPoint)
    def OnCustomContextMenu(self, point):
        menu = QtGui.QMenu()

        # Actions
        action_set_t = QtGui.QAction('Set grade threshold...', self.treeView, triggered=lambda: self.SetThreshold())
        action_restore = QtGui.QAction('Show All', self.treeView, triggered=lambda: self.Restore())
        action_export_trace = QtGui.QAction('Export this trace...', self.treeView, triggered=lambda: self.SaveTrace())
        action_close_viewer = QtGui.QAction('Close Viewer', self.treeView, triggered=lambda: self.Close(4))

        # add actions to menu
        menu.addAction(action_set_t)
        menu.addAction(action_restore)
        menu.addAction(action_export_trace)
        menu.addSeparator()
        menu.addAction(action_close_viewer)

        menu.exec_(self.treeView.viewport().mapToGlobal(point))

    @QtCore.Slot(str)
    def SetThreshold(self):
        threshold = AskLong(-1, 'There are a total of %s grades: %s. Specify a threshold which lines to display:' % (len(self.grades), ''.join('%s ' % c for c in self.grades)))
        if threshold in self.grades:
            self.PopulateModel(threshold)


    @QtCore.Slot(str)
    def SaveTrace(self):  #TODO
        if self.save is not None:
            self.save(self.trace)

    @QtCore.Slot(str)
    def Restore(self):
        self.PopulateModel(0)