# coding=utf-8
__author__ = 'Anatoli Kalysch'

from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore, QtWidgets
# from PyQt5 import QtGui, QtCore, QtWidgets


####################
### STACK CHANGE ###
####################
class StackChangeViewer(PluginViewer):
    def __init__(self, vr, sorted, stack_changes, title='Stack Changes Analysis'):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(StackChangeViewer, self).__init__(title)
        self.vr = vr
        self.sorted = sorted
        self.stack_changes = stack_changes


    def PopulateModel(self):
        for key in self.sorted:
            sa = QtGui.QStandardItem('%s' % key)
            chg = QtGui.QStandardItem('%s' % self.stack_changes[key])

            if key in self.vr.values():
                reg = QtGui.QStandardItem('%s' % [k for k in self.vr.keys() if self.vr[k] == key][0])
            else:
                reg = QtGui.QStandardItem(' ')
            self.sim.appendRow([sa, reg, chg])


        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)


    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()
        self.sim.setHorizontalHeaderLabels(['Stack Address', 'Address Mapped to CPU Reg', 'Value Changes during Execution'])

        # tree view
        self.treeView = QtWidgets.QTreeView()
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        ### populate widgets
        # fill model with data
        self.PopulateModel()

        self.treeView.setModel(self.sim)
        # finalize layout
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.treeView)

        self.parent.setLayout(layout)


    def isVisible(self):
        try:
            return self.treeView.isVisible()
        except:
            return False
