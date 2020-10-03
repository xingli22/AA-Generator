import json


def load_manifest(file_name):
    manifest_file = json.load(open(file_name, 'r'))
    return manifest_file


def load_all_manifests():
    return


if __name__ == '__main__':
    load_manifest("../resources/manifest_files/bookinfo/bookinfo-details-v1.json")
