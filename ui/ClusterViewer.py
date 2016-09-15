# coding=utf-8
__author__ = 'Anatoli Kalysch'

import re


from copy import deepcopy
from ui.NotifyProgress import NotifyProgress
from _collections import defaultdict, deque
from lib.VMRepresentation import get_vmr
from dynamic.TraceRepresentation import Traceline
from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui, QtCore
from lib.TraceAnalysis import cluster_removal

from idaapi import is_basic_block_end
from idc import AskLong


###########################
### CLUSTERING ANALYSIS ###
###########################
class ClusterViewer(PluginViewer):
    def __init__(self, clustered_trace, bb_func, ctx_reg_size, title='Clustering Analysis Result', save_func=None):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(ClusterViewer, self).__init__(title)
        self.orig_trace = clustered_trace
        self.trace = deepcopy(self.orig_trace)
        self.bb_func = bb_func
        self.ctx_reg_size = ctx_reg_size
        self.save = save_func
        self.undo_stack = deque([deepcopy(self.trace)], maxlen=3)

    def PopulateModel(self):
        self.Clean()
        vmr = get_vmr()
        w = NotifyProgress()
        w.show()
        ctr = 0
        max = len(self.trace)

        # present clustering analysis in viewer
        prev_ctx = defaultdict(lambda: 0)
        for line in self.trace:

            ctr += 1
            w.pbar_set(int(float(ctr) / float(max) * 100))

            if isinstance(line, Traceline):
                tid = QtGui.QStandardItem('%s' % line.thread_id)
                addr = QtGui.QStandardItem('%x' % line.addr)
                disasm = QtGui.QStandardItem(line.disasm_str())
                comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
                context = QtGui.QStandardItem(''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx if line.ctx is not None))
                prev_ctx = line.ctx
                self.sim.appendRow([tid, addr, disasm, comment, context])
            else:
                cluster_node = QtGui.QStandardItem('Cluster %x-%x' % (line[0].addr, line[-1].addr))
                self.sim.appendRow(cluster_node)
                if vmr.bb:
                    cluster = line
                    bbs = []
                    bb = []
                    # subdivide the clusters by basic blocks
                    for line in cluster:
                        assert isinstance(line, Traceline)
                        if is_basic_block_end(line.addr):
                            bb.append(line)
                            bbs.append(bb)
                            bb = []
                        else:
                            bb.append(line)

                    for bb in bbs:

                        bb_sum = self.bb_func(bb, self.ctx_reg_size, prev_ctx)
                        bb_node = QtGui.QStandardItem(
                            'BB%s Summary %x-%x: %s\t%s\t%s' % (bbs.index(bb), bb[0].addr, bb[-1].addr,
                                                                ''.join('%s ; ' % (''.join('%s, ' % c for c in line)) for line in bb_sum.disasm),
                                                                ''.join('%s, ' % c for c in filter(None, bb_sum.comment) if bb_sum.comment is not None),
                                                                ''.join('%s:%s ' % (c, bb_sum.ctx[c]) for c in bb_sum.ctx if bb_sum.ctx is not None)))
                        for line in bb:
                            tid = QtGui.QStandardItem('%s' % line.thread_id)
                            addr = QtGui.QStandardItem('%x' % line.addr)
                            disasm = QtGui.QStandardItem(line.disasm_str())
                            comment = QtGui.QStandardItem(''.join(c for c in line.comment if line.comment is not None))
                            context = QtGui.QStandardItem(
                                ''.join('%s:%s ' % (c, line.ctx[c]) for c in line.ctx if line.ctx is not None))
                            bb_node.appendRow([tid, addr, disasm, comment, context])
                        cluster_node.appendRow(bb_node)
                        self.treeView.setFirstColumnSpanned(bbs.index(bb), cluster_node.index(), True)

                        prev_ctx = bb[-1].ctx
                else:
                    for l in line:
                        tid = QtGui.QStandardItem('%s' % l.thread_id)
                        addr = QtGui.QStandardItem('%x' % l.addr)
                        disasm = QtGui.QStandardItem(l.disasm_str())
                        comment = QtGui.QStandardItem(''.join(c for c in l.comment if l.comment is not None))
                        context = QtGui.QStandardItem(
                            ''.join('%s:%s ' % (c, l.ctx[c]) for c in l.ctx if l.ctx is not None))
                        cluster_node.appendRow([tid, addr, disasm, comment, context])

        w.close()

        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)
        self.treeView.resizeColumnToContents(3)
        self.treeView.resizeColumnToContents(4)

    def Clean(self):
        self.sim.clear()
        self.sim.setHorizontalHeaderLabels(['ThreadId', 'Address', 'Disasm', 'Stack Comment', 'CPU Context'])

    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()

        # tree view
        self.treeView = QtGui.QTreeView()
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.treeView.setToolTip('Filter instructions/clusters/basic blocks from trace by double clicking on them.')
        # Context menus
        self.treeView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.treeView.customContextMenuRequested.connect(self.OnCustomContextMenu)

        self.treeView.doubleClicked.connect(self.ItemDoubleClickSlot)
        self.treeView.setModel(self.sim)

        ### populate widgets
        # fill model with data
        self.PopulateModel()

        # self.treeView.setFirstColumnSpanned(0, self.treeView.rootIndex(), True)
        # finalize layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.treeView)

        self.parent.setLayout(layout)

    def isVisible(self):
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
        s = index.data(0)
        print s
        line_index = []
        inner_cluster_index = []
        if s.startswith('Cluster'):
            addrs = re.findall(r'Cluster (.*-.*)', s)[0]
            addrs = addrs.split('-')
            start = int(addrs[0], 16)
            end = int(addrs[1], 16)
            for line in self.trace:
                if isinstance(line, Traceline):
                    continue
                elif isinstance(line, list):
                    if start == line[0].addr and end == line[-1].addr:
                        line_index.append(line)

        elif s.startswith('BB'):
            addrs = re.findall(r'BB.*Summary (.*-.*): .*', s)[0]
            addrs = addrs.split('-')
            bad_range = range(int(addrs[0], 16), int(addrs[1], 16))
            for line in self.trace:
                if isinstance(line, Traceline):
                    continue
                elif isinstance(line, list):
                    for l in line:
                        if l.addr in bad_range:
                            inner_cluster_index.append(l)
        else:  # assume trace line
            for line in self.trace:
                if isinstance(line, Traceline) and line.to_str_line().__contains__(s):
                    line_index.append(line)
                elif isinstance(line, list):
                    for l in line:
                        if l.to_str_line().__contains__(s):
                            line_index.append(line)

        self.undo_stack.append(deepcopy(self.trace))

        for line in line_index:
            self.trace.remove(line)

        for line in self.trace:
            if isinstance(line, list):
                for l in line:
                    if l in inner_cluster_index:
                        line.remove(l)

        self.PopulateModel()

    @QtCore.Slot(QtCore.QPoint)
    def OnCustomContextMenu(self, point):
        menu = QtGui.QMenu()
        init_index = self.treeView.indexAt(point)
        index = self.treeView.indexAt(point)
        level = 0
        while index.parent().isValid():
            index = index.parent()
            level += 1

        text = 'Remove Line'

        if level == 0:
            text = "Remove Cluster / Line"
        elif level == 1 and get_vmr().bb:
            text = "Remove Basic Block"
        elif level == 2:
            text = "Remove Line"
        try:
            action_remove = QtGui.QAction(text, self.treeView, triggered=lambda: self.ItemDoubleClickSlot(init_index))
            menu.addAction(action_remove)
            menu.addSeparator()
        except:
            print '[*] An Exception occured, remove action could not be added to the menu!'
        # Actions
        action_remove_threshold = QtGui.QAction('Remove several clusters...', self.treeView, triggered=lambda: self.ClusterRemoval())

        action_undo = QtGui.QAction('Undo', self.treeView, triggered=lambda: self.Undo())
        action_restore = QtGui.QAction('Restore original trace', self.treeView, triggered=lambda: self.Restore())
        action_export_trace = QtGui.QAction('Export this trace ...', self.treeView,
                                            triggered=lambda: self.SaveTrace())
        action_close_viewer = QtGui.QAction('Close Viewer', self.treeView, triggered=lambda: self.Close(4))

        # add actions to menu
        menu.addAction(action_remove_threshold)
        menu.addAction(action_undo)
        menu.addAction(action_restore)
        menu.addAction(action_export_trace)
        menu.addSeparator()
        menu.addAction(action_close_viewer)

        menu.exec_(self.treeView.viewport().mapToGlobal(point))

    @QtCore.Slot(str)
    def ClusterRemoval(self):
        threshold = AskLong(1, 'How many most common clusters do you want removed?')
        self.undo_stack.append(deepcopy(self.trace))
        self.trace = cluster_removal(deepcopy(self.trace), threshold=threshold)
        self.PopulateModel()

    @QtCore.Slot(str)
    def SaveTrace(self):
        if self.save is not None:
            self.save(self.trace)

    @QtCore.Slot(str)
    def Undo(self):
        self.trace = self.undo_stack[-1]
        self.PopulateModel()

    @QtCore.Slot(str)
    def Restore(self):
        self.undo_stack = deque([deepcopy(self.trace)], maxlen=3)
        self.trace = deepcopy(self.orig_trace)
        self.PopulateModel()
