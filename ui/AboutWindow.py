# coding=utf-8
__author__ = 'Anatoli Kalysch'

from UIManager import QtCore, QtWidgets

class AboutWindow(QtWidgets.QDialog):
    def __init__(self, *args, **kwargs):
        super(AboutWindow, self).__init__(*args, **kwargs)
        self.setFixedSize(600, 250)
        self.setWindowTitle("About ...")
        self.title = "VMAttack IDA PRO Plugin"
        self.subtitle = "IDA Pro Plugin for static and dynamic virtualization-obfuscation analysis and deobfuscation"
        self.author = u"Anatoli Kalysch and Tobias Krauß"
        self.thanks = u"Special thanks to Johannes Götzfried for conceptual help along the way!"
        self.version = "Version 0.2"
        self.address = "Friedrich-Alexander University Erlangen-Nuremberg\n i1 Software Security Research Group \n"

        try:
            title = self.config_label(self.title, 16, True)
            subtitle = self.config_label(self.subtitle, 14)
            subtitle.move(0, title.height() + title.y() + 10)
            version = self.config_label(self.version, 12)
            version.move(0, subtitle.height() + subtitle.y() + 30)
            author = self.config_label(self.author, 12)
            author.move(0, version.height() + version.y())
            thanks = self.config_label(self.thanks, 12)
            thanks.move(0, author.height() + author.y())
        except Exception, e:
            print e.message

        self.show()

    def config_label(self, name, size, bold=False, alignment="center"):
        label = QtWidgets.QLabel(name, self)
        label.setWordWrap(True)
        font = label.font()
        font.setPointSize(size)
        font.setBold(bold)
        label.setFont(font)
        if alignment == "center":
            label.setAlignment(QtCore.Qt.AlignCenter)
        elif alignment == "right":
            label.setAlignment(QtCore.Qt.AlignRight)
        elif alignment == "left":
            label.setAlignment(QtCore.Qt.AlignLeft)
        label.setFixedWidth(600)

        return label
