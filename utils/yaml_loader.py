import yaml


def load_yamls(yaml_name):
    files = yaml.load_all(open(yaml_name, 'r').read(), Loader=yaml.FullLoader)
    return files


def load_yaml(yaml_name):
    file = yaml.load(open(yaml_name, 'r').read(), Loader=yaml.FullLoader)
    return file


if __name__ == '__main__':
    load_yamls("../resources/deployment_files/bookinfo.yaml")
