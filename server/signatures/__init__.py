"""
Load all the signature files into a single dictionary.
"""
import os
import glob
import yaml

dictionary = {}

signature_files = glob.glob(os.path.dirname(__file__)+"/*.json")

# loading using pyyaml to allow safe loading of str variables (not unicode)
for s in signature_files:
    with open(os.path.abspath(s)) as signature_file:
        dictionary[os.path.basename(s)[:-5]] = yaml.safe_load(signature_file)

del signature_files
