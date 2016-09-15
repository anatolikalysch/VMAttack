# coding=utf-8
__author__ = 'Anatoli Kalysch'

from UIManager import QtGui, QtCore

class NotifyProgress(QtGui.QWidget):
    def __init__(self, name='current', *args, **kwargs):
        super(NotifyProgress, self).__init__(*args, **kwargs)
        self.analysis = name
        self.pbar = QtGui.QProgressBar(self)
        self.pbar.setGeometry(30, 40, 370, 25)
        self.value = 0
        self.setFixedSize(400, 100)
        self.setWindowTitle('Running %s Analysis...' % self.analysis)

    def pbar_update(self, value):
        self.value += value
        if self.value > 100:
            self.value = 100
            self.close()
        self.pbar.setValue(self.value)

    def pbar_set(self, value):
        self.pbar.setValue(value)

