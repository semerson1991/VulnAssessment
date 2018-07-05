
class Host:
    def __init__(self, host):
        self.ip = host.address
        self.mac = host.mac
        self.uptime = host.uptime
        self.vendor = host.vendor
        if host.os.osclasses:
            osdetails = host.os.osclasses[0]
            self.osfamily = osdetails.osfamily
            self.osgen = osdetails.osgen
            self.osaccuracy = osdetails.accuracy

        if host.status == 'up':
            self.status = 'up'
        else:
            self.status = 'down'
        self.services = []