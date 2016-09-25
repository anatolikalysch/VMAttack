# coding=utf-8
__author__ = 'Anatoli Kalysch'

from idaapi import Form, BADADDR
from lib.VMRepresentation import get_vmr, VMContext


class SettingsView(Form):
    def __init__(self):
        Form.__init__(self, ("STARTITEM 0\n"
                             "BUTTON YES* Confirm\n"
                             "BUTTON CANCEL Cancel\n"
                             "VMAttack Settings\n"
                             "\n"
                             "VM Values:\n"
                             "<Byte code start           :{iCodeStart}>\n"
                             "<Byte code end             :{iCodeEnd}>\n"
                             "<Jump table base address   :{iBaseAddr}>\n"
                             "<VM function address       :{iVMAddr}>\n"
                             "\n"
                             "Clustering:\n"
                             "<Show basic blocks:{rShowBB}>\n"
                             "<Greedy clustering:{rGreedyCluster}>{cClusterValues}>\n"
                             "<Cluster Heuristic         :{iClusterHeu}>\n"
                             "\n"
                             "Grading Automation:\n"
                             "<Input/Output Importance   :{iInOut}>\n"
                             "<Clustering Importance     :{iClu}>\n"
                             "<Pattern Importance        :{iPaMa}>\n"
                             "<Memory Usage Importance   :{iMeUs}>\n"
                             "<Static Analysis Importance:{iSta}>\n"
                             "\n"
                             "\n"
                             "Dynamic Analysis:\n"
                             "<Step Into System Libraries :{rStepInSysLibs}>\n"
                             '<Extract function parameters:{rFuncParams}>{cDynamicValues}>\n'
                             ), {
                          'cClusterValues': Form.ChkGroupControl(("rShowBB", "rGreedyCluster")),
                          'cDynamicValues': Form.ChkGroupControl(('rStepInSysLibs', 'rFuncParams')),
                          'iClusterHeu': Form.NumericInput(tp=Form.FT_DEC),
                          'iInOut': Form.NumericInput(tp=Form.FT_DEC),
                          'iClu': Form.NumericInput(tp=Form.FT_DEC),
                          'iPaMa': Form.NumericInput(tp=Form.FT_DEC),
                          'iMeUs': Form.NumericInput(tp=Form.FT_DEC),
                          'iSta': Form.NumericInput(tp=Form.FT_DEC),
                          'iVMAddr': Form.NumericInput(tp=Form.FT_DEC),
                          'iBaseAddr': Form.NumericInput(tp=Form.FT_DEC),
                          'iCodeEnd': Form.NumericInput(tp=Form.FT_DEC),
                          'iCodeStart': Form.NumericInput(tp=Form.FT_DEC),
                      })

    def OnButtonNop(self, code=0):
        pass

def Show():
    settings = SettingsView()
    settings.Compile()
    vmr = get_vmr()
    vm_ctx = vmr.vm_ctx

    settings.iCodeStart.value = vm_ctx.code_start
    settings.iCodeEnd.value = vm_ctx.code_end
    settings.iBaseAddr.value = vm_ctx.base_addr
    settings.iVMAddr.value = vm_ctx.vm_addr

    settings.rGreedyCluster.checked = vmr.greedy
    settings.rShowBB.checked = vmr.bb
    settings.iClusterHeu.value = vmr.cluster_magic

    settings.iInOut.value = vmr.in_out
    settings.iClu.value = vmr.clu
    settings.iPaMa.value = vmr.pa_ma
    settings.iMeUs.value = vmr.mem_use
    settings.iSta.value = vmr.static

    settings.rStepInSysLibs.checked = vmr.sys_libs
    settings.rFuncParams.checked = vmr.extract_param

    if settings.Execute() == 0:  # Cancel
        settings.Free()
    else:  # Confirm
        vmr = get_vmr()
        # VM values
        vm_ctx = VMContext()
        vm_ctx.code_start = settings.iCodeStart.value
        vm_ctx.code_end = settings.iCodeEnd.value
        vm_ctx.base_addr = settings.iBaseAddr.value
        vm_ctx.vm_addr = settings.iVMAddr.value

        vmr.vm_ctx = vm_ctx

        vmr.in_out = settings.iInOut.value
        vmr.clu = settings.iClu.value
        vmr.pa_ma = settings.iPaMa.value
        vmr.mem_use = settings.iMeUs.value
        vmr.static = settings.iSta.value

        # Env values
        vmr.sys_libs = settings.rStepInSysLibs.checked
        vmr.extract_param = settings.rFuncParams.checked
        vmr.greedy = settings.rGreedyCluster.checked
        vmr.bb = settings.rShowBB.checked
        vmr.cluster_magic = settings.iClusterHeu.value

        settings.Free()
