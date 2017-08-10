#!/usr/bin/env python2
# coding=utf-8
__author__ = 'Anatoli Kalysch'

import pip
import sys
from os import getcwd, system, remove
from shutil import copyfile


def do(action, dependency):
    return pip.main([action, dependency])


def usage():
    print "Usage: python2 setup.py <install | uninstall>"


dependencies = ["distorm3", 'idacute']

if __name__ == '__main__':

    stub_name = 'VMAttack_plugin_stub.py'
    for dependency in dependencies:
        try:
            if sys.argv[1]:
                print '[*] Starting dependency handling!'
                if sys.argv[1] in ["install", "uninstall"]:
                    retval = do(sys.argv[1], dependency)
                else:
                    retval = do("install", dependency)
                if retval == 0:
                    continue
                else:
                    print '[!] An error occured! Please resolve issues with dependencies and try again.'
            else:
                raise IndexError()
        except IndexError:
            usage()
            sys.exit(1)

    try:
        if sys.argv[1] == 'uninstall':
            with open('install_dir') as f:
                ida_dir = f.read()
            if ida_dir:
                remove(ida_dir + stub_name)
                sys.exit(0)
    except:
        pass

    print '[*] Setting up environment and installing Plugin.'
    # set up environment variable on Windows: setx Framework C:\path\to\Framework\
    plugin_dir = getcwd()
    system('setx VMAttack %s' % plugin_dir)
    # copy stub into the IDA PRO Plugin directory
    ida_dir = raw_input('Please input full path to the IDA *plugin* folder (e.g. X:\IDA\plugins\): ')
    if not ida_dir.endswith(r'\\'):
        ida_dir += r'\\'
    with open('install_dir', 'w') as f:
        f.write(ida_dir)
    copyfile(stub_name, ida_dir + stub_name)
    print '[*] Install complete. All Done!'
