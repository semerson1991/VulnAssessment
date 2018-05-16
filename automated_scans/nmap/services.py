class Services:
    def __init__(self, service):
        self.protocol = service.protocol
        self.service = service.service
        self.port = service.port
        self.state = service.state

