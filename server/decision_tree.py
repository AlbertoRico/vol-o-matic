"""
Data structures for the decision tree
"""


class Runner:
    """
    Decision tree algorithm. Executes deciders.
    """
    def __init__(self, analyzer, signatures, deciders, threshold, early_response=None):
        self.analyzer = analyzer
        self.signatures = signatures
        self.threshold = threshold
        self.deciders = deciders

        if hasattr(early_response, '__call__'):
            self.early_response = early_response
        else:
            def no_function():
                print "Breach detected!"

            self.early_response = no_function

    def run(self):
        final_decision = Decision()

        for decider in self.deciders:
            # aggregate every decision into one
            current_decision = decider.decide(self.analyzer, self.signatures)
            final_decision = final_decision + current_decision

            # if threshold is reached, execute early response
            if(final_decision.get_breach() >= self.threshold):
                self.early_response()

        return final_decision


class Decider:
    """
    Abstract. Must be implemented by the deciders loaded in the runner.
    """
    @staticmethod
    def decide(analyzer, signatures):
        raise NotImplementedError("Deciders must implement 'decide()'")


class Decision:
    """
    Conclusions achieved by the decider. Addition of two decisions results in
    concatenation of their indicators of compromise, and addition of the breach boolean.

    Attributes:
        breach (boolean): Assessed breach
        ioc_list (list): List of indicators of compromise
    """
    def __init__(self, ioc_list=[], breach=False):
        self.ioc_list = ioc_list
        self.breach = breach

    def get_ioc_list(self):
        return self.ioc_list

    def get_breach(self):
        return self.breach

    def add_ioc(self, ioc):
        self.ioc_list.append(ioc)

    def add_ioc_list(self, ioc_list):
        self.ioc_list += ioc_list

    def set_breach(self, breach):
        self.breach = breach

    def __add__(self, decision):
        return Decision(
                self.ioc_list + decision.get_ioc_list(),
                self.breach + decision.get_breach()
                )

    def __str__(self):
        custom_string = ""

        if (self.breach):
            custom_string = custom_string + "Breach detected!\n"
        else:
            custom_string = custom_string + "No breach detected.\n"

        for ioc in self.ioc_list:
            for entry in ioc:
                custom_string = custom_string + " - " + str(entry)
            custom_string = custom_string + "\n"

        return custom_string


class IndicatorOfCompromise:
    """
    Indicator of compromise, as found by a decider.

    Attributes:
        ioc_list (list): List of indicators of compromise

    """
    def __init__(self, decider_name, raw_data, readable_string):
        self.decider_name = decider_name
        self.raw_data = raw_data
        self.readable_string = readable_string

    def get_raw_data(self):
        return self.raw_data

    def set_raw_data(self, raw_data):
        self.raw_data = raw_data

    def get_readable_string(self):
        return self.readable_string

    def set_readable_string(self, readable_string):
        self.readable_string = readable_string

    def get_decider_name(self):
        return self.decider_name

    def set_decider_name(self, decider_name):
        self.decider_name = decider_name

    def __str__(self):
        return self.get_readable_string()
