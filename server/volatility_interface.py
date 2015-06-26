import sys

sys.path.insert(0, '../volatility-2.4.zip/volatility-2.4/')

import volatility.plugins as plugins
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace


class Analyzer:
    def __init__(self, image_path):
        """
        Create a new Analyzer, with a given image_path
        """
        registry.PluginImporter()

        self.config = conf.ConfObject()

        registry.register_global_options(self.config, commands.Command)
        registry.register_global_options(self.config, addrspace.BaseAddressSpace)

        # self.config.PROFILE = "WinXPSP3x86"
        self.config.LOCATION = image_path

        self.config.parse_options()

    def get_config(self):
        """
        Return the current config (address space parsing, when analyzing)
        """
        return self.config

    def run_plugin(self, plugin_name, plugin_method):
        """
        Dynamically run a plugin
        """
        return self.get_plugin(plugin_name, plugin_method).calculate()

    def get_plugin(self, plugin_name, plugin_method):
        """
        Dynamically get a plugin
        """
        module = self.get_module(plugin_name)
        init_plugin = getattr(module, plugin_method)

        i = init_plugin(self.config)

        return i

    def get_module(self, plugin_name):
        """
        Dynamically get a module, containing plugins, iterating over a path
        """
        module_list = plugin_name.split(".")
        pointer = 0

        module = plugins

        while pointer < len(module_list):
            module = getattr(module, module_list[pointer])
            pointer += 1


        return module
