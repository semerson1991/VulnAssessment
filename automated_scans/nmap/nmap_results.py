from libnmap.parser import NmapParser

from automated_scans.nmap.host import Host
from automated_scans.nmap.services import Services
from automated_scans.security.cryptography import Encryptor
import os
class NmapResult:

    def __init__(self):
        self.hosts = []

    def add_hosts(self, nmap_report):

        for scanned_host in nmap_report.hosts:
            host = Host(scanned_host)
            the_services = scanned_host.services

            services = []
            for service in the_services:
                service_info = Services(service)
                services.append(service_info)

            host.services = services
            self.hosts.append(host)

    def get_results(self, network_mapper_report_path, key):
        print('Getting Network Mapper report')
        test = key

        encryptor = Encryptor(key)
        encryptor.decrypt_file(network_mapper_report_path + '.enc')

        with open(network_mapper_report_path, 'rb') as fo:
            source = fo.read()

        nmap_report = NmapParser.parse(source.decode("utf-8"))

        fo.close()
        os.remove(network_mapper_report_path)
        self.add_hosts(nmap_report)
