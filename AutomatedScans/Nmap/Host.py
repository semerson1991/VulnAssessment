
class Host:

    def __init__(self, host):
        self.ip = host.address
        self.os = host.os_fingerprint

    def addServices(self, services):
        self.services = services


