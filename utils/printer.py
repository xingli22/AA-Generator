import yaml


def output(target, app_name, path):
    policy = open(path + app_name + '.yaml', 'w+')
    yaml.dump_all(target, policy)
    policy.close()


def phase_1_output(role, binding, app, service_name, path):
    role_file = open(path + app + '-' + service_name + '-role.yaml', 'w+')
    binding_file = open(path + app + '-' + service_name + '-binding.yaml', 'w+')
    yaml.dump_all(role, role_file)
    yaml.dump_all(binding, binding_file)
    role_file.close()
    binding_file.close()
