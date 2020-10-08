import copy
import threading
import time
from pprint import pprint

from numpy import std, mean

from model.graph import Graph
from model.permission import Permission
from model.permission_node import PermissionNode
from utils.manifest_loader import load_manifest
from utils.printer import output, phase_1_output, output_name
from utils.registrant import register, clean_registration, get_registration
from utils.yaml_loader import load_yaml, load_yamls

manifest_prefix = {'10': 'resources/manifest_files/large_scale/10/10-',
                   '20': 'resources/manifest_files/large_scale/20/20-',
                   '30': 'resources/manifest_files/large_scale/30/30-',
                   '40': 'resources/manifest_files/large_scale/40/40-',
                   '50': 'resources/manifest_files/large_scale/50/50-'}
manifest_suffix = '.json'
deployment_prefix = 'resources/deployment_files/large_scale/'
deployment_suffix = '.yaml'
registration_file = "resources/registration"
role_temp_path = 'resources/templates/role.yaml'
binding_temp_path = 'resources/templates/binding.yaml'
policy_temp_path = "resources/templates/policy.yaml"
rule_temp_path = 'resources/templates/rule.yaml'
traffic_base = 'resources/traffic_management_rules/'
output_path = 'output/large_scale/'
# registration = []
cache = {}
policy_r = {}
policy_b = {}
new_phase_1 = 0
graph = Graph("")


def build_permission(request):
    permission = ""
    if request['name'] != '':  # todo: for external access
        if request['type'] == 'http':
            permission = Permission("http", request['name'], request["path"], request["method"], "")
        elif request['type'] == 'grpc':
            permission = Permission("grpc", request['name'], request["path"], "", "")
        elif request['type'] == 'tcp':
            permission = Permission("tcp", request['name'], "", "", request['port'])
        else:
            print('[AA error]: unknown request type')
    return permission


def build_policy_with_version(current_node, permission):
    policy_temp = load_yaml(policy_temp_path)
    policy = copy.deepcopy(policy_temp)
    policy['metadata']['name'] = current_node.service_name + '-' + current_node.service_version + '-' + str(
        permission.get_hashcode())
    policy['metadata']['namespace'] = graph.application_name  # todo: need confirmation
    policy['spec']['selector']['matchLabels']['app'] = permission.target_service

    service_account = graph.application_name + '-' + current_node.service_name
    if current_node.service_account != '':
        service_account = current_node.service_account

    rule = load_yaml(rule_temp_path)
    if permission.type == 'http':
        del rule['to'][0]['operation']['ports']
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account)
        rule['to'][0]['operation']['methods'].append(permission.method)
        rule['to'][0]['operation']['paths'].append(permission.path)
        # rule['when'][0]['values'].append(current_node.service_version)
        del rule['when']
        # pprint(rule)
    elif permission.type == 'grpc':
        del rule['to'][0]['operation']['ports']
        del rule['to'][0]['operation']['methods']
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account)
        rule['to'][0]['operation']['paths'].append(permission.path)
        # rule['when'][0]['values'].append(current_node.service_version)
        del rule['when']
    elif permission.type == 'tcp':
        del rule['to'][0]['operation']['methods']
        del rule['to'][0]['operation']['paths']
        rule['to'][0]['operation']['ports'].append(permission.port)
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account)
        # pprint(rule['when'][0])
        # rule['when'][0]['values'].append(current_node.service_version)
        del rule['when']
        # pprint(rule)
    else:
        print('error: unknown request kind')

    policy['spec']['rules'].append(rule)
    # pprint(policy)
    return policy


def build_policy_without_version(current_node, permission):
    policy_temp = load_yaml(policy_temp_path)
    policy = copy.deepcopy(policy_temp)
    policy['metadata']['name'] = current_node.service_name + '-' + current_node.service_version + '-' + str(
        permission.get_hashcode())
    policy['metadata']['namespace'] = graph.application_name  # todo: need confirmation
    policy['spec']['selector']['matchLabels']['app'] = permission.target_service

    service_account_prefix = graph.application_name.replace('-', '')
    rule = load_yaml(rule_temp_path)
    if permission.type == 'http':
        del rule['to'][0]['operation']['ports']
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account_prefix + '-' + current_node.service_name)
        rule['to'][0]['operation']['methods'].append(permission.method)
        rule['to'][0]['operation']['paths'].append(permission.path)
        del rule['when']
        # rule['when'][0]['values'].append(current_node.service_version)
        # pprint(rule)
    elif permission.type == 'grpc':
        del rule['to'][0]['operation']['ports']
        del rule['to'][0]['operation']['methods']
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account_prefix + '-' + current_node.service_name)
        rule['to'][0]['operation']['paths'].append(permission.path)
        del rule['when']
    elif permission.type == 'tcp':
        del rule['to'][0]['operation']['methods']
        del rule['to'][0]['operation']['paths']
        rule['to'][0]['operation']['ports'].append(permission.port)
        rule['from'][0]['source']['principals'].append(
            'cluster.local/ns/' + graph.application_name + '/sa/' + service_account_prefix + '-' + current_node.service_name)
        # pprint(rule['when'][0])
        del rule['when']
        # pprint(rule)
    else:
        print('error: unknown request kind')

    policy['spec']['rules'].append(rule)
    # pprint(policy)
    return policy


def policy_generation(app, ifversion, mode, islist):
    phase_1 = 0
    deployment_path = deployment_prefix + app + '-' + mode + deployment_suffix
    # time1 = time.time()
    temp_data = []
    deployment_data = load_yamls(deployment_path)
    if islist:
        for loaded_data in deployment_data:
            if loaded_data.get('kind') == 'List':
                temp_data = loaded_data.get('items')
        deployment_data = temp_data

    # time2 = time.time()
    # print(time2-time1)
    roles = {}
    bindings = {}
    policies = []
    # graph = Graph(app)

    candidate_nodes = set()

    for yaml_data in deployment_data:
        if yaml_data is not None:
            if yaml_data.get('kind') == 'Deployment':  # deployment: generate from template
                # build the node
                if 'labels' not in yaml_data.get('metadata') and app != 'boutique':
                    print('[AA error]: deployment ' + yaml_data.get('metadata').get('name') + ' no labels')
                    continue
                if 'labels' not in yaml_data.get('metadata') and app == 'boutique' and (mode.startswith('multi')):
                    service_name = yaml_data.get('spec').get('selector').get('matchLabels').get('app')
                    service_version = yaml_data.get('spec').get('selector').get('matchLabels').get('version')
                else:
                    if 'app' not in yaml_data.get('metadata').get('labels'):
                        service_name = yaml_data.get('metadata').get('labels').get('name')
                    else:
                        service_name = yaml_data.get('metadata').get('labels').get('app')
                    service_version = yaml_data.get('metadata').get('labels').get('version')
                if service_version == None:
                    service_version = 'v1'  # todo default v1
                    print('[AA error]: deployment ' + service_name + ' no version')
                node = PermissionNode(service_name, service_version)
                manifest_path = manifest_prefix[app] + service_name + '-' + service_version + manifest_suffix
                try:
                    manifest_file = load_manifest(manifest_path)
                except FileNotFoundError:
                    #print('[AA error]: ' + manifest_path + ' not found')
                    graph.add_node(node)
                    continue
                requests = manifest_file['requests']
                for request in requests:
                    permission = build_permission(request)
                    if permission == "":
                        continue
                    #if permission.target_service in graph.registration:
                    # todo: registered by default
                    permission.active = True
                    candidate_nodes.add(node)
                    # else:
                    #     if permission.target_service not in cache:
                    #         cache[permission.target_service] = []
                    #     cache[permission.target_service].append(node)
                    node.grant_permission(permission)

                equal_with_exist_node = graph.add_node(node)
                if equal_with_exist_node is True:
                    node.set_covered()
                    if node in candidate_nodes:
                        candidate_nodes.remove(node)

            elif yaml_data.get('kind') == 'Service':  # service: register it
                # if 'labels' not in yaml_data.get('metadata'):
                service_name = yaml_data.get('metadata').get('name')
                # else:
                #     service_name = yaml_data.get('metadata').get('labels').get('app')
                graph.register(service_name)
                if service_name in cache and len(cache[service_name]) != 0:
                    # active permissions after registration
                    for node in cache[service_name]:
                        for permission in node.permissions.values():
                            if permission.active is False and permission.target_service == service_name:
                                permission.active = True
                        if not node.covered:
                            candidate_nodes.add(node)
                    del cache[service_name]
                # pprint(cache)
                # if service_name in cache.keys():
                #     for caller, permissions in cache[service_name].items():
                #         strs = caller.split('-')
                #         version = strs[len(strs) - 1]
                #         permissions = phase_3_scan_traffic(caller, version, permissions, app, type)
                #         roles[caller]['spec']['rules'].extend(permissions)
                #     cache.pop(service_name)
            else:
                print('[AA error]: unsupported yaml kind')

    # finish deployment file analysis, start to generate policies
    build_start = time.time()
    for current_node in candidate_nodes:
        if len(current_node.permissions) != 0:
            for permission in current_node.permissions.values():
                if permission.active is True and permission.generated is False:
                    if ifversion:
                        policy = build_policy_with_version(current_node, permission)
                    else:
                        policy = build_policy_without_version(current_node, permission)
                    permission.generated = True
                    policies.append(policy)
        else:
            print('[AA error]: candidate does not have permissions')
    build_end = time.time()
    build_time = (build_end - build_start) * 1000
    # pprint(roles)
    return policies, build_time


def remove(app, ifversion, mode, islist):
    phase_1 = 0
    deployment_path = deployment_prefix + app + '-' + mode + deployment_suffix
    # time1 = time.time()
    temp_data = []
    deployment_data = load_yamls(deployment_path)
    if islist:
        for loaded_data in deployment_data:
            if loaded_data.get('kind') == 'List':
                temp_data = loaded_data.get('items')
        deployment_data = temp_data

    # time2 = time.time()
    # print(time2-time1)
    roles = {}
    bindings = {}
    policies = []
    # graph = Graph(app)

    candidate_nodes = set()
    policy_path = output_path + app + '-ordered.yaml'
    existing_policies_1 = list(load_yamls(policy_path))
    policy_path = output_path + app + '-second.yaml'
    existing_policies_2 = list(load_yamls(policy_path))

    for yaml_data in deployment_data:
        if yaml_data is not None:
            if yaml_data.get('kind') == 'Deployment':  # deployment: generate from template
                # build the node
                if 'labels' not in yaml_data.get('metadata'):
                    print('[AA error]: deployment ' + yaml_data.get('metadata').get('name') + ' no labels')
                    continue
                if 'app' not in yaml_data.get('metadata').get('labels'):
                    service_name = yaml_data.get('metadata').get('labels').get('name')
                else:
                    service_name = yaml_data.get('metadata').get('labels').get('app')
                service_version = yaml_data.get('metadata').get('labels').get('version')
                if service_version == None:
                    service_version = 'noversion'
                    print('[AA error]: deployment ' + service_name + ' no version')
                node = PermissionNode(service_name, service_version)
                service_account = yaml_data.get('spec').get('template').get('spec').get('serviceAccountName')
                if service_account is not None:
                    node.set_service_account(service_account)
                graph.remove_node(node)

                for existing_policy in existing_policies_1:
                    if existing_policy['spec']['rules'][0]['from'][0]['source'][
                        'principals'] == 'cluster.local/ns/' + app + '/sa/' + app + '-' + service_name + '-' + service_version:
                        policies.append(existing_policy['metadata']['name'])
                        existing_policies_1.remove(existing_policy)

                for existing_policy in existing_policies_2:
                    if existing_policy['spec']['rules'][0]['from'][0]['source'][
                        'principals'] == 'cluster.local/ns/' + app + '/sa/' + app + '-' + service_name + '-' + service_version:
                        policies.append(existing_policy['metadata']['name'])
                        existing_policies_2.remove(existing_policy)
            else:
                print('[AA error]: unsupported yaml kind')

    build_time = 0
    return policies, build_time


if __name__ == '__main__':

    apps = ['10', '20', '30', '40', '50']
    modes = ['ordered', 'second', 'remove', 'multi', 'multisa']
    version = False
    islist = False

    this_app = 4
    this_mode = 0
    this_round = 1

    app_name = apps[this_app]
    # clean_registration(registration_file)
    # type = '11'

    mode = modes[this_mode]
    before = []
    after = []

    process_time_1 = []
    process_time_2 = []
    process_time_3 = []
    build_times = []

    for i in range(this_round):
        graph = Graph(app_name)

        if this_mode > 2:
            pass
        else:
            start_time_1 = time.time()
            mode = modes[0]
            policies, build_time_1 = policy_generation(app_name, version, mode, islist)
            output(policies, app_name + '-' + mode, output_path)
            end_time_1 = time.time()
            total_time_1 = (end_time_1 - start_time_1) * 1000
            process_time_1.append(total_time_1)

            start_time_2 = time.time()
            mode = modes[1]
            policies, build_time_2 = policy_generation(app_name, version, mode, islist)
            output(policies, app_name + '-' + mode, output_path)
            end_time_2 = time.time()
            total_time_2 = (end_time_2 - start_time_2) * 1000
            process_time_2.append(total_time_2)

            start_time_3 = time.time()
            mode = modes[2]
            policies, build_time_3 = remove(app_name, version, mode, islist)
            output_name(policies, app_name + '-' + mode, output_path)
            end_time_3 = time.time()
            total_time_3 = (end_time_3 - start_time_3) * 1000
            process_time_3.append(total_time_3)

            print('Great! You made it!!!')

        # build_times.append(build_time)
        # print(total_time)

    mean_time_1 = mean(process_time_1)
    std_time_1 = std(process_time_1)
    mean_time_2 = mean(process_time_2)
    std_time_2 = std(process_time_2)
    mean_time_3 = mean(process_time_3)
    std_time_3 = std(process_time_3)
    # mean_build_time = mean(build_times)
    print('d-mean: %d std: %.2f' % (round(mean_time_1), round(std_time_1, 2)))
    print('rd-mean: %d std: %.2f' % (round(mean_time_2), round(std_time_2, 2)))
    print('r-mean: %d std: %.2f' % (round(mean_time_3), round(std_time_3, 2)))
    # print(mean_build_time)

    #     start_time = time.time()
    #     roles, bindings, phase_1 = tests[this_test](app_name, type, mode)
    #     output(roles, app_name, 'roles', type, output_path)
    #     output(bindings, app_name, 'bindings', type, output_path)
    #     end_time = time.time()
    #     total_time = end_time - start_time
    #     ave_time = total_time * 1000  # / number[app_name] / 2
    #     before.append(ave_time)
    #     new_ave_time = (total_time - phase_1) * 1000  # / number[app_name] / 2
    #     after.append(new_ave_time)
    #     clean_registration(registration_file)
    #     cache = {}
    #     policy_r = {}
    #     policy_b = {}
    #     new_phase_1 = 0
    #
    #
    # mean_before = mean(before)
    # # print('mean before is %.2f' % mean_before)
    # mean_after = mean(after)
    # print('mean after is %.2f' % mean_after)
    # std_before = std(before)
    # # print('std before is %.2f' % std_before)
    # std_after = std(after)
    # print('std after is %.2f' % std_after)
