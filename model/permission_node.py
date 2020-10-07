class PermissionNode:

    def __init__(self, service_name, service_version):
        self.service_name = service_name
        self.service_version = service_version
        self.service_account = ''
        self.permissions = {}
        self.covered = False

    def set_service_account(self, service_account):
        self.service_account = service_account

    def grant_permission(self, permission):
        permission_hash = permission.get_hashcode()
        self.permissions[permission_hash] = permission

    def node_compare(self, node):
        this_hashs = list(self.permissions.keys())
        node_hashs = list(node.permissions.keys())
        if this_hashs.sort() == node_hashs.sort():
            return True
        else:
            return False

    def set_covered(self):
        self.covered = True
