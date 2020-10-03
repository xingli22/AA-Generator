import copy
import threading
import time
from pprint import pprint

from numpy import std, mean

from utils.manifest_loader import load_manifest
from utils.printer import output, phase_1_output
from utils.registrant import register, clean_registration, get_registration
from utils.yaml_loader import load_yaml, load_yamls

manifest_prefix = {'bookinfo': 'resources/manifest_files/bookinfo/bookinfo-',
                   'onlineboutique': 'resources/manifest_files/onlineboutique/onlineboutique-',
                   'sockshop': 'resources/manifest_files/sockshop/sockshop-'}
manifest_suffix = '.json'
deployment_prefix = 'resources/deployment_files/'
deployment_suffix = '.yaml'
registration_file = 'resources/registration'
role_temp_path = 'resources/templates/role.yaml'
binding_temp_path = 'resources/templates/binding.yaml'
rule_temp_path = 'resources/templates/rule.yaml'
traffic_base = 'resources/traffic_management_rules/'
output_path = 'output/'
# registration = []
cache = {}
policy_r = {}
policy_b = {}
new_phase_1 = 0
new_phase_3 = 0
manifest_file_map = {}


def get_template():
    role_temp = load_yaml(role_temp_path)
    binding_temp = load_yaml(binding_temp_path)
    # pprint(role_temp)
    # pprint(binding_temp)
    return role_temp, binding_temp


def phase_1_generate_template(app, service_name, requests):
    role, binding = get_template()
    role['metadata']['name'] = service_name
    role['metadata']['namespace'] = app  # todo: need confirmation
    binding['metadata']['name'] = 'bind-' + service_name
    binding['metadata']['namespace'] = app  # todo: need confirmation
    binding['spec']['subjects'][0]['user'] = 'cluster.local/ns/default/sa/' + service_name
    binding['spec']['roleRef']['name'] = service_name
    rules = []

    rule_template = load_yaml(rule_temp_path)
    for request in requests:
        if request['name'] != '':  # todo: for external access
            if request['type'] == 'http':
                rule = copy.deepcopy(rule_template)
                rule['constraints'].pop()
                rule['services'].append(request['name'] + '.' + app + '.' + 'svc.cluster.local')
                rule['methods'].append(request['method'])
                rule['paths'].append(request['path'])
                # pprint(rule)
                rules.append(rule)
            elif request['type'] == 'grpc':
                rule = copy.deepcopy(rule_template)
                rule['constraints'].pop()
                rule['services'].append(request['name'] + '.' + app + '.' + 'svc.cluster.local')
                rule['methods'].append('PUT')
                rule['paths'].append(request['path'])
                rules.append(rule)
            elif request['type'] == 'tcp':
                rule = copy.deepcopy(rule_template)
                rule['constraints'].pop(0)
                rule['constraints'].pop(0)
                rule['constraints'][0]['values'].append(request['port'])
                rule['services'].append(request['name'] + '.' + app + '.' + 'svc.cluster.local')
                rule.pop('methods')
                rule.pop('paths')
                rules.append(rule)
            else:
                print('error: unknown request kind')
    # else:
    # print('cache: the callee has not been registered')

    role['spec']['rules'] = rules
    # pprint(role)
    # phase_1_output(role, binding, app, service_name, output_path + 'phase_1/')
    return role, binding


def phase_2_complete_template(caller, rules):
    for rule in rules[:]:
        service_name = rule['services'][0].split('.')[0]
        if service_name not in get_registration(registration_file):
            print('cache: the callee has not been registered')
            if service_name not in cache.keys():
                cache[service_name] = {}
            if caller not in cache[service_name].keys():
                cache[service_name][caller] = []
            cache[service_name][caller].append(rule)
            rules.remove(rule)

    # pprint(cache)
    return rules


def phase_3_scan_traffic(caller, version, rules, app, type):
    for rule in rules:
        service_name = rule['services'][0].split('.')[0]
        traffic_path = traffic_base + app + '-vs-' + type + '.yaml'
        traffics = load_yamls(traffic_path)
        callee_version = ''
        for traffic in traffics:
            if traffic['metadata']['name'] == service_name:
                for route in traffic['spec']['http']:
                    if route['match'][0]['sourceLabels']['version'] == version:
                        callee_version = route['route'][0]['destination']['subset']

                for constraint in rule['constraints']:
                    if 'request.headers[version]' == constraint['key']:
                        constraint['value'].append(version)
                    if 'destination.labels[version]' == constraint['key']:
                        # pprint(traffic)
                        constraint['value'].append(callee_version)

        # pprint(rule)
    return rules


class processer(threading.Thread):
    def __init__(self, target, istart, iend, app, type):
        threading.Thread.__init__(self)
        self.target = target
        self.istart = istart
        self.iend = iend
        self.app = app
        self.type = type

    def run(self):
        for index in range(self.istart, self.iend):
            yaml_data = self.target[index]
            if yaml_data is not None:
                if yaml_data.get('kind') == 'Deployment':  # deployment: generate from template
                    service_name = yaml_data.get('metadata').get('name')
                    manifest_path = manifest_prefix[self.app] + service_name + manifest_suffix
                    try:
                        manifest_file = load_manifest(manifest_path)
                    except FileNotFoundError:
                        print(manifest_path + ' not found')
                        continue
                    # pprint(manifest_file)
                    requests = manifest_file['requests']

                    # todo: the 1st phase: generate from template
                    phase_1_start_time = time.time()
                    role, binding = phase_1_generate_template(self.app, service_name, requests)
                    phase_1_end_time = time.time()
                    phase_1_time = phase_1_end_time - phase_1_start_time
                    global new_phase_1
                    new_phase_1 += phase_1_time
                    # pprint(new_phase_1)

                    # todo: the 2nd phase: generate from registration
                    rules = role['spec']['rules']
                    role['spec']['rules'] = phase_2_complete_template(service_name, rules)
                    # pprint(cache)

                    # todo: the 3rd phase: generate from traffic management rules
                    rules = role['spec']['rules']
                    version = yaml_data['metadata']['labels']['version']
                    role['spec']['rules'] = phase_3_scan_traffic(service_name, version, rules, self.app, self.type)
                    # pprint(role)
                    policy_r[service_name] = role
                    policy_b[service_name] = binding


def generate_for_batch_optimized(app, type, mode):
    phase_1 = 0
    deployment_path = deployment_prefix + app + '-' + mode + deployment_suffix
    deployment_data = load_yamls(deployment_path)
    roles = {}
    data = []
    bindings = {}
    for yaml_data in deployment_data:
        if yaml_data is not None:
            if yaml_data.get('kind') == 'Service':  # service: register it
                service_name = yaml_data.get('metadata').get('name')
                # registration.append(service_name)
                register(registration_file, service_name)
                # deployment_data.remove(yaml_data)

                # todo: add the 4th phase after registration
                # pprint(cache)
                if service_name in cache.keys():
                    for caller, permissions in cache[service_name].items():
                        strs = caller.split('-')
                        version = strs[len(strs) - 1]
                        permissions = phase_3_scan_traffic(caller, version, permissions, app, type)
                        roles[caller]['spec']['rules'].extend(permissions)
                    cache.pop(service_name)
            else:
                data.append(yaml_data)

    for yaml_data in data:
        if yaml_data.get('kind') == 'Deployment':  # deployment: generate from template
            service_name = yaml_data.get('metadata').get('name')
            manifest_path = manifest_prefix[app] + service_name + manifest_suffix
            try:
                manifest_file = load_manifest(manifest_path)
            except FileNotFoundError:
                print(manifest_path + ' not found')
                continue
            # pprint(manifest_file)
            requests = manifest_file['requests']

            # todo: the 1st phase: generate from template
            phase_1_start_time = time.time()
            role, binding = phase_1_generate_template(app, service_name, requests)
            phase_1_end_time = time.time()
            phase_1_time = phase_1_end_time - phase_1_start_time
            phase_1 += phase_1_time

            # todo: the 2nd phase: generate from registration
            rules = role['spec']['rules']
            role['spec']['rules'] = phase_2_complete_template(service_name, rules)
            # pprint(cache)

            # todo: the 3rd phase: generate from traffic management rules
            rules = role['spec']['rules']
            version = yaml_data['metadata']['labels']['version']
            role['spec']['rules'] = phase_3_scan_traffic(service_name, version, rules, app, type)
            # pprint(role)
            roles[service_name] = role
            bindings[service_name] = binding
    return roles, bindings, phase_1


def generate_for_batch_optimized_mt(app, type, mode):
    phase_1 = 0
    deployment_path = deployment_prefix + app + '-' + mode + deployment_suffix
    deployment_data = load_yamls(deployment_path)
    data = []
    roles = {}
    bindings = {}
    for yaml_data in deployment_data:
        if yaml_data is not None:
            if yaml_data.get('kind') == 'Service':  # service: register it
                service_name = yaml_data.get('metadata').get('name')
                # registration.append(service_name)
                register(registration_file, service_name)
                # deployment_data.remove(yaml_data)

                # todo: add the 4th phase after registration
                # pprint(cache)
                if service_name in cache.keys():
                    for caller, permissions in cache[service_name].items():
                        strs = caller.split('-')
                        version = strs[len(strs) - 1]
                        permissions = phase_3_scan_traffic(caller, version, permissions, app, type)
                        roles[caller]['spec']['rules'].extend(permissions)
                    cache.pop(service_name)
            else:
                data.append(yaml_data)

    # for yaml_data in deployment_data:
    length = len(data)
    pprint(length)
    x = 3
    thd_num = length // x
    if length % x != 0:
        thd_num += 1
    print(thd_num)
    thd_list = []
    for i in range(0, thd_num - 1):
        mythd = processer(data, i * (length // (thd_num - 1)), (i + 1) * (length // (thd_num - 1)), app, type)
        # pprint(str(mythd.istart) + ':' + str(mythd.iend))
        mythd.start()
        thd_list.append(mythd)
    mylastthd = processer(data, length // (thd_num - 1) * (thd_num - 1), length, app, type)
    mylastthd.start()
    # pprint(str(mylastthd.istart) + ':' + str(mylastthd.iend))
    thd_list.append(mylastthd)

    for thd in thd_list:
        thd.join()
    # pprint(policy_b)

    # pprint(roles)
    return policy_r, policy_b, new_phase_1 / thd_num


def hash_requests(service_name, requests):
    start = service_name.split('-')[0]
    hash_code = ''
    role = ''
    request_map = {}
    request_list = []
    for request in requests:
        str_base = ''
        if request['type'] == 'http':
            str_base = request['name'] + request['path'] + request['method']
        elif request['type'] == 'grpc':
            str_base = request['name'] + request['path']
        else:
            str_base = request['name'] + str(request['port'])
        hash_code += str(hash(str_base))
        request_map[hash(str_base)] = request
    print(hash_code)
    if start not in manifest_file_map.keys():
        manifest_file_map[start] = {}
    else:
        if hash_code not in manifest_file_map[start].keys():
            for key in manifest_file_map[start].keys():
                if hash_code.find(key) != -1:
                    print('yohoo')
                    new_hash_code = hash_code.replace(key, '')
                    role = manifest_file_map[start][key]

                    request_list.append(request_map[int(new_hash_code)])
                    return new_hash_code, True, role, request_list
            # manifest_file_map[hash_code] = {}
        else:
            role = manifest_file_map[start][hash_code]
            return hash_code, True, role, request_list
    return hash_code, False, role, request_list


def generate_for_batch_original(app, type, mode, v):
    phase_1 = 0
    phase_3 = 0
    deployment_path = deployment_prefix + app + '-' + mode + v + deployment_suffix
    # time1 = time.time()
    deployment_data = load_yamls(deployment_path)
    time2 = time.time()
    # print(time2-time1)
    roles = {}
    bindings = {}
    for yaml_data in deployment_data:
        if yaml_data is not None:
            if yaml_data.get('kind') == 'Deployment':  # deployment: generate from template
                service_name = yaml_data.get('metadata').get('name')
                manifest_path = manifest_prefix[app] + service_name + manifest_suffix
                try:
                    manifest_file = load_manifest(manifest_path)
                except FileNotFoundError:
                    print(manifest_path + ' not found')
                    continue
                # pprint(manifest_file)
                requests = manifest_file['requests']
                # todo: hash the requests
                start = service_name.split('-')[0]

                hash_code, flag, ro, others = hash_requests(service_name, requests)
                if flag:
                    print('good')
                    roles[service_name] = ro[0]
                    bindings[service_name] = ro[1]
                    pprint(others)
                    continue

                # todo: the 1st phase: generate from template
                phase_1_start_time = time.time()
                role, binding = phase_1_generate_template(app, service_name, requests)
                phase_1_end_time = time.time()
                phase_1_time = phase_1_end_time - phase_1_start_time
                phase_1 += phase_1_time

                # todo: the 2nd phase: generate from registration
                rules = role['spec']['rules']
                role['spec']['rules'] = phase_2_complete_template(service_name, rules)
                # pprint(cache)

                # todo: the 3rd phase: generate from traffic management rules
                phase_3_start_time = time.time()
                rules = role['spec']['rules']
                version = yaml_data['metadata']['labels']['version']
                role['spec']['rules'] = phase_3_scan_traffic(service_name, version, rules, app, type)
                # pprint(role)
                roles[service_name] = role
                bindings[service_name] = binding
                if start not in manifest_file_map.keys():
                    manifest_file_map[start] = {}
                manifest_file_map[start][hash_code] = (role, binding)
                phase_3_end_time = time.time()
                phase_3_time = phase_3_end_time - phase_3_start_time
                phase_3 += phase_3_time

            elif yaml_data.get('kind') == 'Service':  # service: register it
                service_name = yaml_data.get('metadata').get('name')
                # registration.append(service_name)
                register(registration_file, service_name)
                # todo: add the 4th phase after registration
                # pprint(cache)
                if service_name in cache.keys():
                    for caller, permissions in cache[service_name].items():
                        strs = caller.split('-')
                        version = strs[len(strs) - 1]
                        permissions = phase_3_scan_traffic(caller, version, permissions, app, type)
                        roles[caller]['spec']['rules'].extend(permissions)
                    cache.pop(service_name)
            else:
                print('error: unknown yaml kind')

    # pprint(roles)
    return roles, bindings, phase_1, phase_3


if __name__ == '__main__':

    this_time = 2
    this_mode = 0
    this_test = 0
    this_round = 20
    apps = ['bookinfo', 'onlineboutique', 'sockshop']
    app_name = apps[this_time]

    number = {'bookinfo': 4, 'onlineboutique': 5, 'sockshop': 7}
    type = '11'
    modes = ['best', 'worst']
    tests = [generate_for_batch_original, generate_for_batch_optimized, generate_for_batch_optimized_mt]
    mode = modes[this_mode]
    before = []
    after = []
    update = []

    for i in range(this_round):
        start_time = time.time()
        roles, bindings, phase_1, phase_3 = tests[this_test](app_name, type, mode, '1')
        output(roles, app_name, 'roles', type, output_path)
        output(bindings, app_name, 'bindings', type, output_path)
        end_time = time.time()
        total_time = end_time - start_time
        new_ave_time = (total_time - phase_1) * 1000 / number[app_name]
        after.append(new_ave_time)

        print('ok')
        start_time1 = time.time()
        roles, bindings, phase_11, x = tests[this_test](app_name, type, mode, '2')
        output(roles, app_name, 'roles', type, output_path)
        output(bindings, app_name, 'bindings', type, output_path)
        end_time1 = time.time()
        total_time1 = end_time1 - start_time1
        ave_time1 = (total_time1 + phase_1) * 1000 / number[app_name]
        update.append(ave_time1)

        clean_registration(registration_file)
        manifest_file_map = {}
        cache = {}
        policy_r = {}
        policy_b = {}
        new_phase_1 = 0

        print('Great! You made it!!!' + str(phase_1))
    mean_after = mean(after)
    print('mean after is %.2f' % mean_after)
    std_after = std(after)
    print('std after is %.2f' % std_after)

    mean_update = mean(update)
    print('mean update is %.2f' % mean_update)
    std_update = std(update)
    print('std update is %.2f' % std_update)
