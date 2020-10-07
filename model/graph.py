class Graph:

    def __init__(self, application_name):
        self.application_name = application_name
        self.nodes = {}
        self.registration = set()

    def get_deploymented_service_number(self):
        return len(self.nodes)

    def add_node(self, node): # return if equal with existing node
        if_equal = False

        if node.service_name not in self.nodes:
            self.nodes[node.service_name] = {}
        else:
            old_node = list(self.nodes[node.service_name].values())[0]  #todo: use the first one for easy
            if_equal = node.node_compare(old_node)

        self.nodes[node.service_name][node.service_version] = node

        return if_equal
        # if node.service_name not in self.registration:
        #     self.registration.append(node.service_name)

    def remove_node(self, node):
        if node.service_name in self.nodes:
            versions = self.nodes[node.service_name]
            if node.service_version in versions:
                versions.pop(node.service_version)
                if len(versions) == 0:
                    self.nodes.pop(node.service_name)
            else:
                print("[AA Error]: "+node.service_name+" do not have version "+ node.service_version)
        else:
            print("[AA Error]: " + self.application_name + " do not have service "+node.service_name)

    def register(self, service_name):
        self.registration.add(service_name)
