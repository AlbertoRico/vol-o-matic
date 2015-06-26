import sys
sys.path.insert(0, '../decision_tree')
import decision_tree


class ImageInfo(decision_tree.Decider):
    """
    Analyzes the image for general information
    """
    @staticmethod
    def decide(analyzer, signatures):
        risk = 0
        ioc_list = []

        aux = analyzer.run_plugin("imageinfo", "ImageInfo")

        for i in aux:
            print i

        return decision_tree.Decision(ioc_list, risk)


def load_decider():
    return ImageInfo
