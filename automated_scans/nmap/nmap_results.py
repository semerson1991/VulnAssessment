from libnmap.parser import NmapParser

from automated_scans.nmap.host import Host
from automated_scans.nmap.services import Services


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