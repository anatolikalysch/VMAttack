# coding=utf-8
__author__ = 'Anatoli Kalysch'

from idaapi import PluginForm, msg
from ui.UIManager import form_to_widget


class PluginViewer(PluginForm):
    def __init__(self, title):
        super(PluginViewer, self).__init__()
        self.title = title

    def Show(self, **kwargs):
        return PluginForm.Show(self, self.title, options=PluginForm.FORM_PERSIST)

    def OnCreate(self, form):
        # Get parent widget
        self.parent = form_to_widget(form)
        self.PopulateForm()

    def PopulateForm(self):
        ### do stuff
        pass

    def OnClose(self, form):
        msg("Closed %s.\n" % self.title)