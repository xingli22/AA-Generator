class Graph:

    def __init__(self, application_name):
        self.application_name = application_name
        self.nodes = {}
        self.registration = set()

    def add_node(self, node): # return if equal with existing node
        if_equal = False

        if node.service_name not in self.nodes:
            self.nodes[node.service_name] = []
        else:
            old_node = self.nodes[node.service_name][0] #todo: use the first one for easy
            if_equal = node.node_compare(old_node)

        self.nodes[node.service_name].append(node)

        return if_equal
        # if node.service_name not in self.registration:
        #     self.registration.append(node.service_name)

    def register(self, service_name):
        self.registration.add(service_name)
