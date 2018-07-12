

class NmapScanConfig():
    def __init__(self):
        self.scanType = 'Network Scan'
        self.scan_technique = ''
        self.port_range = ''
        self.hosts = ''
        self.detections_ops = ''
        self.custom_args = ''

    def getScanTechnique(self):
        if self.scan_technique == 'Stealth':
            return '-sS'
        elif self.scan_technique == 'TCP Connect':
            return '-sT'
        elif self.scan_technique == 'UDP':
            return '-sU'
        elif self.scan_technique == 'FIN':
            return '-sF'
        elif self.scan_technique == 'Null':
            return '-sN'
        elif self.scan_technique == 'Xmas':
            return '-sX'

        return '-sS'

    def getPortRange(self):
        if self.port_range == 'All':
            return '-'
        if self.port_range == 'Common':
            return ' 0-1024'
        return ' '+ self.port_range

    def getNetworkDetectionOps(self):
        if self.detections_ops == 'Operating System':
            return '-O'
        elif self.detections_ops == 'Operating Systems & Service Versions':
            return '-A'
        return 'None'