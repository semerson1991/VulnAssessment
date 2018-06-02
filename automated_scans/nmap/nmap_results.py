from libnmap.parser import NmapParser

from automated_scans.nmap.host import Host
from automated_scans.nmap.services import Services


class NmapResults:

    def __init__(self):
        self.hosts = []

    def add_hosts(self, nmap_report):

        for scanned_hosts in nmap_report.hosts:
            host = Host(scanned_hosts)
            the_services = scanned_hosts.services

            services = []
            for service in the_services:
                service_info = Services(service)
                services.append(service_info)

            host.services = services
            self.hosts.append(host)