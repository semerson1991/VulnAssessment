from authentication import utils


class ScanResults():
    def __init__(self):
        self.nmap_result = None
        self.openvas_result = []
        self.results_collected = False
        self.scan_id = utils.create_uuid()