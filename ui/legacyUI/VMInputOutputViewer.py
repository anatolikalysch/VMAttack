# coding=utf-8
__author__ = 'Anatoli Kalysch'
from copy import deepcopy

from dynamic.TraceRepresentation import Traceline
from lib.Register import get_reg_class
from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore


#############################
### INPUT OUTPUT ANALYSIS ###
#############################
class VMInputOuputViewer(PluginViewer):
    def __init__(self, input_set, output_set, output_ctx, title='Input/Output Analysis (legacy)'):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(VMInputOuputViewer, self).__init__(title)
        self.input = input_set
        self.output = output_set
        self.ctx = output_ctx
        self.selection = {'upper':[], 'lower':[]}
        self.ucb_map = []
        self.lcb_map = []
        # brush map
        self.brush_map = {0:QtGui.QBrush(QtCore.Qt.white),  # unselected values
                          1:QtGui.QBrush(QtGui.QColor(228,153,105)),  # input values color
                          2:QtGui.QBrush(QtGui.QColor(183,166,173)),  # output values color
                          3:QtGui.QBrush(QtGui.QColor(157,151,84))}  # BOTH values, mix of both colors

    def PopulateModel(self):
        assert isinstance(self.ctx, dict)
        for key in self.ctx.keys():
            if get_reg_class(key) is not None:
                node = QtGui.QStandardItem('Register %s' % key)
                node_brush = set()
                for line in self.ctx[key]:
                    assert isinstance(line, Traceline)
                    tid = QtGui.QStandardItem('%s' % line.thread_id)
                    addr = QtGui.QStandardItem('%x' % line.addr)
                    disasm = QtGui.QStandardItem(line.disasm_str())
                    comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
                    context = QtGui.QStandardItem(''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx.keys() if line.ctx is not None))
                    ci = 0
                    co = 0
                    for selector in self.selection['upper']:  # check input values
                        if line.to_str_line().__contains__(selector) or line.to_str_line().__contains__(selector.lower()):
                            ci = 1

                    for selector in self.selection['lower']: # check output values
                        if line.to_str_line().__contains__(selector) or line.to_str_line().__contains__(selector.lower()):
                            co = 2

                    node_brush.add(ci+co)
                    tid.setBackground(self.brush_map[ci+co])
                    addr.setBackground(self.brush_map[ci+co])
                    disasm.setBackground(self.brush_map[ci+co])
                    comment.setBackground(self.brush_map[ci+co])
                    context.setBackground(self.brush_map[ci+co])

                    node.appendRow([tid, addr, disasm, comment, context])
                try:
                    node.setBackground(self.brush_map[max(node_brush)])
                except:
                    pass
                self.sim.appendRow(node)

        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)
        self.treeView.resizeColumnToContents(3)
        self.treeView.resizeColumnToContents(4)


    def PopulateUpperToolbar(self):
        assert isinstance(self.input, set)
        self.utb.addWidget(QtGui.QLabel('Input values found (check to highlight in trace): '))
        for value in self.input:
            self.ucb_map.append(QtGui.QCheckBox(value))
            self.ucb_map[-1].stateChanged.connect(lambda: self.OnValueChecked())
            self.utb.addWidget(self.ucb_map[-1])
            self.utb.addSeparator()

    def PopulateLowerToolbar(self):
        assert isinstance(self.input, set)
        self.ltb.addWidget(QtGui.QLabel('Output values found (check to highlight in trace): '))
        for value in self.output:
            self.lcb_map.append(QtGui.QCheckBox(value))
            self.lcb_map[-1].stateChanged.connect(lambda: self.OnValueChecked())
            self.ltb.addWidget(self.lcb_map[-1])
            self.ltb.addSeparator()

    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

        # toolbar
        self.utb = QtGui.QToolBar()
        self.ltb = QtGui.QToolBar()
        # tree view
        self.treeView = QtGui.QTreeView()
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.treeView.setToolTip('Highlights:\n Rust red - Input\n Violet - Output\n Olive - Both')

        ### populate widgets
        # fill model with data
        self.PopulateModel()
        # fill toolbar with data
        self.PopulateUpperToolbar()
        self.PopulateLowerToolbar()
        self.treeView.setModel(self.sim)
        # finalize layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.utb)
        layout.addWidget(self.treeView)
        layout.addWidget(self.ltb)

        self.parent.setLayout(layout)

    def CleanModel(self):
        self.sim.clear()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

    def OnValueChecked(self):
        for check_box in self.ucb_map:
            if check_box.isChecked() and check_box.text() not in self.selection['upper']:
                self.selection['upper'].append(check_box.text())
            elif not check_box.isChecked() and check_box.text() in self.selection['upper']:
                self.selection['upper'].remove(check_box.text())

        for check_box in self.lcb_map:
            if check_box.isChecked() and check_box.text() not in self.selection['lower']:
                self.selection['lower'].append(check_box.text())
            elif not check_box.isChecked() and check_box.text() in self.selection['lower']:
                self.selection['lower'].remove(check_box.text())
        self.CleanModel()
        self.PopulateModel()

    def isVisible(self):
        try:
            return self.treeView.isVisible()
        except:
            return False
