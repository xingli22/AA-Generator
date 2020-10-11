import copy
import json
import threading
import time
from pprint import pprint

from numpy import std, mean

from model.graph import Graph
from model.permission import Permission
from model.permission_node import PermissionNode
from utils.manifest_loader import load_manifest
from utils.printer import output, phase_1_output, output_name, json_write
from utils.registrant import register, clean_registration, get_registration
from utils.yaml_loader import load_yaml, load_yamls

manifest_prefix = {'bookinfo': '../resources/manifest_files/bookinfo/bookinfo-',
                   'boutique': '../resources/manifest_files/boutique/boutique-',
                   'sockshop': '../resources/manifest_files/sockshop/sockshop-',
                   'pitstop': '../resources/manifest_files/pitstop/pitstop-',
                   'sitewhere': '../resources/manifest_files/sitewhere/sitewhere-'}
manifest_suffix = '.json'
deployment_prefix = '../resources/deployment_files/'
deployment_suffix = '.yaml'
sitewhere_temp_path = '../resources/templates/sitewhere_requests.yaml'
sitewhere_dep_path = '../resources/deployment_files/sitewhere-ordered.yaml'

manifest_temp = {
  "service": "instance-management",
  "version": "v1",
  "requests": []
}

pass_service = ['cp-zookeeper','cp-kafka', 'mongodb', 'influxdb', 'cassandra']




def old_way():
    temp_data = []
    sitewhere_data = load_yamls(sitewhere_temp_path)
    #json_temp = json.load(manifest_temp)


    for yaml_data in sitewhere_data:
        if yaml_data is not None:
            for v in range(2):
                json_temp = copy.deepcopy(manifest_temp)
                service_name = yaml_data['name']
                version = 'v'+str(v+1)
                json_temp['service'] = service_name
                json_temp['version'] = version
                requests = yaml_data['requests']
                for request in requests:
                    if request['type'] == 'grpc':
                        target_name = request['target']
                        num = request['num']
                        for i in range(num):
                            this_request = {}
                            this_request['type'] = 'grpc'
                            this_request['url'] = ''
                            this_request['name'] = target_name
                            this_request['path'] = '/'+str(i)
                            json_temp['requests'].append(this_request)
                    elif request['type'] == 'tcp':
                        target_name = request['target']
                        this_request = {}
                        this_request['type'] = 'tcp'
                        this_request['url'] = ''
                        this_request['name'] = target_name
                        this_request['port'] = '12345'
                        json_temp['requests'].append(this_request)
                    elif request['type'] == 'http':
                        target_name = request['target']
                        num = request['num']
                        for i in range(num):
                            this_request = {}
                            this_request['type'] = 'http'
                            this_request['url'] = ''
                            this_request['name'] = ''
                            this_request['method'] = 'GET'
                            this_request['path'] = '/' + str(i)
                            json_temp['requests'].append(this_request)

                #pprint(json_temp)
                json_write(json_temp, manifest_prefix['sitewhere']+service_name+'-'+version+'.json')


def dep_gen(version):
    temp_data = []
    sitewhere_data = load_yamls(sitewhere_dep_path)
    #json_temp = json.load(manifest_temp)

    new_dep = []
    file = {}
    for yaml_data in sitewhere_data:
        if yaml_data is not None:
            if yaml_data['kind'] == 'Deployment':
                if 'labels' not in yaml_data['metadata'] or yaml_data['metadata']['labels']['app'] in pass_service:
                    continue
                file = dict(yaml_data)
                file['metadata']['labels']['version'] = version
                new_dep.append(file)

    if version == 'v1':
        output(new_dep, 'sitewhere-remove', deployment_prefix)
    if version == 'v2':
        output(new_dep, 'sitewhere-second', deployment_prefix)


if __name__ == '__main__':
    old_way()
    dep_gen('v1')
    dep_gen('v2')