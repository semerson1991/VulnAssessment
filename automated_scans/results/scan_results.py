from authentication import utils


class ScanResults():
    def __init__(self):
        self.nmap_result = None
        self.openvas_result = []
        self.results_collected = False
        self.scan_id = str(utils.create_uuid())
        self.action = 'results-collected' #THIS COULD BE ADDED SEPERATELY INSTEAD (Before sending back to client)


    def cleanup(self, openvas_report):
        self.openvas_result.remove(openvas_report)
        self.nmap_result = None