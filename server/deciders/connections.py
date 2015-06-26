import sys
sys.path.insert(0, '../decision_tree')
import decision_tree


class Connections(decision_tree.Decider):
    """
    Analyzes the network connection structures in memory
    """
    @staticmethod
    def decide(analyzer, signatures):
        breach = False
        ioc_list = []

        connections_signatures = signatures.get("connections", {})

        behaviour = connections_signatures.get("behaviour", "unknown")
        addresses = connections_signatures.get("addresses", [])
        localports = connections_signatures.get("localports", [])
        remoteports = connections_signatures.get("remoteports", [])

        aux = analyzer.run_plugin("connections", "Connections")

        for i in aux:
            detected_iocs = []

            if behaviour == "blacklist":
                if i.RemoteIpAddress in addresses:
                    detected_iocs.append(i.RemoteIpAddress)

                if i.LocalPort in localports:
                    detected_iocs.append(i.LocalPort)

                if i.RemotePort in remoteports:
                    detected_iocs.append(i.RemotePort)

            elif behaviour == "whitelist":
                if i.RemoteIpAddress not in addresses:
                    detected_iocs.append(i.RemoteIpAddress)

                if i.LocalPort not in localports:
                    detected_iocs.append(i.LocalPort)

                if i.RemotePort not in remoteports:
                    detected_iocs.append(i.RemotePort)

            else:
                raise Exception("unknown behaviour for connections signature")


            if detected_iocs:
                breach = True

                detected_iocs.insert(0, hex(i._vol_offset))
                detected_iocs.insert(0, i.Pid)
                detected_iocs.insert(0, "--Connections IoC--")

                process_info = analyzer.run_plugin("taskmods", "PSList")

                for j in process_info:
                    if j.UniqueProcessId == i.Pid:
                        detected_iocs.insert(1, ""+j.ImageFileName)

                ioc_list.append(detected_iocs)

        return decision_tree.Decision(ioc_list, breach)


def load_decider():
    return Connections
