from AutomatedScans.Nmap.Host import Host
from AutomatedScans.Nmap.Services import Services


class NmapResults:


    def __init__(self):
        self.hosts = []


    def add_hosts(self, nmap_report):

        for scanned_hosts in nmap_report.hosts:
            host = Host(scanned_hosts)
            the_services = scanned_hosts.services


            services = []
            for service in the_services:
                serviceInfo = Services(service)
                services.append(serviceInfo)

            host.addServices(services)
            self.hosts.append(host)
