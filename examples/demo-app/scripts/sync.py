import json


def load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except:
        print("failed")
        return {}
