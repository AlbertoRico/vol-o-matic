import sys
sys.path.insert(0, '../decision_tree')
sys.path.insert(0, '../../volatility-2.4.zip/volatility-2.4/')

import decision_tree

import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.malware.apihooks as apihooks
import volatility.conf as conf

class Rootkits(decision_tree.Decider):
    """
    Analyzes the processes in the image
    """
    @staticmethod
    def decide(analyzer, signatures):
        breach = False
        ioc_list = []

        rootkit_signatures = signatures.get("rootkits", {})

        entries = rootkit_signatures.get("entries", [])

        aux = analyzer.run_plugin("ssdt", "SSDT")
        config_obj = analyzer.get_config()

        addr_space = utils.load_as(config_obj)
        syscalls = addr_space.profile.syscalls

        # Print out the entries for each table
        for idx, table, n, vm, mods, mod_addrs in aux:
            for i in range(n):
                # These are absolute function addresses in kernel memory.
                syscall_addr = obj.Object('address', table + (i * 4), vm).v()

                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(mods, mod_addrs, addr_space.address_mask(syscall_addr))
                if syscall_mod:
                    syscall_modname = syscall_mod.BaseDllName
                else:
                    syscall_modname = "UNKNOWN"

                # must match all values that are filled (empty values accept any)
                for entry in entries:
                    address = entry.get("address", syscall_addr)
                    name = entry.get("name", syscall_name)
                    module = entry.get("module", syscall_modname)

                    matches_rule = address == str(hex(syscall_addr)) and name == str(syscall_name) and module == str(syscall_modname)

                    if matches_rule:
                        ioc_list.append(["-- Rootkits IoC --", str(hex(syscall_addr)) , syscall_name, syscall_modname ])


        return decision_tree.Decision(ioc_list, breach)


def load_decider():
    return Rootkits
