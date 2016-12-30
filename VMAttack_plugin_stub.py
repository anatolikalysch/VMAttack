# coding=utf-8
__author__ = 'Anatoli Kalysch'

import imp
import sys
import os


F_DIR = os.environ["VMAttack"]
F_NAME = "VMAttack.py"
sys.path.append(F_DIR)

plugin_path = os.path.join(F_DIR, F_NAME)
plugin = imp.load_source(__name__, plugin_path)
PLUGIN_ENTRY = plugin.PLUGIN_ENTRY