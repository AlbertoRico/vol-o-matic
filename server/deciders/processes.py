import sys
sys.path.insert(0, '../decision_tree')
import decision_tree
import re

class Processes(decision_tree.Decider):
    """
    Analyzes the processes in the image
    """
    @staticmethod
    def decide(analyzer, signatures):
        breach = False
        ioc_list = []

        processes_signatures = signatures.get("processes", {})
        behaviour = processes_signatures.get("behaviour", "unknown")
        names = processes_signatures.get("names", [])
        sids = processes_signatures.get("sid", {})


        aux = analyzer.run_plugin("taskmods", "PSList")

        for process in aux:
            detected_iocs = []

            process_name = str(process.ImageFileName)

            if behaviour == "blacklist":
                if process_name in names:
                    detected_iocs.append("Blacklisted name")
            elif behaviour == "whitelist":
                if process_name not in names:
                    detected_iocs.append("Name not in whitelist")
            else:
                raise Exception("unknown behaviour for processes signature")

            process_token = process.get_token()
            for sid_pattern in sids.get(process_name, []):
                sid_regex = re.compile(sid_pattern)
                for sid in process_token.get_sids():
                    if behaviour == "blacklist":
                        if sid_regex.match(sid) is not None:
                            breach = True
                            detected_iocs.append("Pattern: " + sid_pattern)
                            detected_iocs.append("SID: " + sid)

                    elif behaviour == "whitelist":
                        if sid_regex.match(sid) is None:
                            breach = True
                            detected_iocs.append("Pattern: " + sid_pattern)
                            detected_iocs.append("SID: " + sid)
                    else:
                        raise Exception("unknown behaviour for processes signature")

            if detected_iocs:
                detected_iocs.insert(0, process_name)
                detected_iocs.insert(0, "--Processes IoC--")
                ioc_list.append(detected_iocs)

        return decision_tree.Decision(ioc_list, breach)


def load_decider():
    return Processes
