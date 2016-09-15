# coding=utf-8
__author__ = 'Anatoli Kalysch'

from cute import QtGui, QtCore, QtWidgets, form_to_widget
import idaapi


class UIManager(object):
    def __init__(self):

        self.window = None
        self.widget = None
        self.menu = None
        self.menu_dict = {}
        self.get_init_menu()

    # initial menu grab
    def get_init_menu(self):
        try:
            self.widget = form_to_widget(idaapi.get_current_tform())
            if self.widget is None:
                raise Exception()
        except:
            self.widget = form_to_widget('Output window')
        self.window = self.widget.window()
        self.menu = self.window.findChild(QtGui.QMenuBar)

    # add top level menu
    def add_menu(self, name):
        if name in self.menu_dict:
            raise Exception("Menu name %s already exists." % name)
        menu = self.menu.addMenu(name)
        self.menu_dict[name] = menu
    # remove top level menu
    def remove_menu(self, name):
        if name not in self.menu_dict:
            raise Exception("Menu %s was not found. It might be deleted, or belong to another menu manager." % name)

        self.menu.removeAction(self.menu_dict[name].menuAction())
        del self.menu_dict[name]

    # remove all menus currently in dict
    def clear(self):
        for menu in self.menu_dict.itervalues():
            self.menu.removeAction(menu.menuAction())
        self.menu_dict = {}

    def add_view(self, view):
        pass
