import copy
import json

from utils import yaml_loader
from utils.printer import output

deployment_temp_path = '../resources/templates/large_scale/service-graph.gen.yaml'
deployment_sec_rem_temp_path = '../resources/templates/large_scale/service-graph.sec:rem.yaml'
output_path = '../resources/deployment_files/large_scale/'
manifest_path = '../resources/templates/large_scale/service-manifest.json'
manifest_output_path_prefix = '../resources/manifest_files/large_scale/'

request = {
    "type": "http",
    "url": "*",
    "name": "details",
    "path": "/api",
    "method": "CALL"
}


def generate_deployment(num):
    deployment_file_list = []
    for i in range(num):
        deployment_template = yaml_loader.load_yamls(deployment_temp_path)
        for yaml_data in deployment_template:
            name = 's' + str(i) + '-' + str(yaml_data.get('metadata').get('name'))
            yaml_data['metadata']['labels']['app'] = name
            if yaml_data.get('kind') == 'Deployment':
                yaml_data['metadata']['labels']['version'] = 'v1'
            deployment_file_list.append(yaml_data)
    output(deployment_file_list, str(num) + '-ordered', output_path)

    deployment_file_list = []
    for i in range(num):
        deployment_template = yaml_loader.load_yamls(deployment_sec_rem_temp_path)
        for yaml_data in deployment_template:
            if yaml_data.get('kind') == 'Service':
                continue

            name = 's' + str(i) + '-' + str(yaml_data.get('metadata').get('name'))
            yaml_data['metadata']['labels']['app'] = name
            if yaml_data.get('kind') == 'Deployment':
                yaml_data['metadata']['labels']['version'] = 'v2'
            deployment_file_list.append(yaml_data)
    output(deployment_file_list, str(num) + '-second', output_path)

    deployment_file_list = []
    for i in range(num):
        deployment_template = yaml_loader.load_yamls(deployment_sec_rem_temp_path)
        for yaml_data in deployment_template:
            if yaml_data.get('kind') == 'Service':
                continue

            name = 's' + str(i) + '-' + str(yaml_data.get('metadata').get('name'))
            yaml_data['metadata']['labels']['app'] = name
            if yaml_data.get('kind') == 'Deployment':
                yaml_data['metadata']['labels']['version'] = 'v1'
            deployment_file_list.append(yaml_data)
    output(deployment_file_list, str(num) + '-remove', output_path)


def load_json():
    with open(manifest_path, 'r') as json_file:
        json_data = json.load(json_file)
        return json_data

def dump_manifest(num,data, service_name):
    with open(manifest_output_path_prefix+str(num)+'/'+service_name, 'w') as manifest_file:
        json.dump(data,manifest_file)


def generate_manifest(num):
    manifest_temp = load_json()
    for i in range(num):
        for version in ('v1', 'v2'):
            big_service = copy.deepcopy(manifest_temp)
            big_service['service'] = 's' + str(i) + '-0'
            big_service_name = 's' + str(i) + '-0'
            big_service['version'] = version
            for j in range(9):
                request_temp = copy.deepcopy(request)
                request_temp['name'] = big_service_name+'-'+str(j)
                big_service['requests'].append(request_temp)
            dump_manifest(num,big_service,str(num)+'-'+big_service_name+'-'+version+'.json')
            for h in range(9):
                small_service = copy.deepcopy(manifest_temp)
                small_service['service'] = big_service_name+'-'+str(h)
                small_service_name = big_service_name+'-'+str(h)
                request_temp = copy.deepcopy(request)
                request_temp['name'] = small_service_name+'-0'
                small_service['requests'].append(request_temp)
                dump_manifest(num, small_service, str(num) + '-' + small_service_name + '-' + version + '.json')



if __name__ == '__main__':
    graph_number = 50
    generate_deployment(graph_number)
    generate_manifest(graph_number)
