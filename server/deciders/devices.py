import sys
sys.path.insert(0, '../decision_tree')
import decision_tree

class Devices(decision_tree.Decider):
    """
    Analyzes the processes in the image
    """
    @staticmethod
    def decide(analyzer, signatures):
        breach = False
        ioc_list = []

        connections_signatures = signatures.get("devices", {})

        behaviour = connections_signatures.get("behaviour", "unknown")
        sets = connections_signatures.get("sets", [])

        aux = analyzer.run_plugin("malware.devicetree", "DeviceTree")

        # elimination strategy
        for i in aux:
            for individual_set in sets:
                id_list = individual_set.get("ids", [])
                if str(i.DriverName) in id_list:
                    id_list.remove(str(i.DriverName))
                    individual_set["ids"] = id_list

                    if len(id_list) == 0:
                        breach = True
                        ioc_list.append(["--Devices IoC--","Set matched", individual_set.get("name")])

        return decision_tree.Decision(ioc_list, breach)


def load_decider():
    return Devices
