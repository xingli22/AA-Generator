class Permission:

    def __init__(self, request_type, target_service, path, method, port):
        self.type = request_type
        self.target_service = target_service
        self.path = path
        self.method = method
        self.port = str(port)
        self.active = False
        self.generated = False
        self.signature = self.type + self.target_service + self.path + self.method + self.port

    def get_hashcode(self):
        hashcode = hash(self.signature)
        return hashcode
