from libnmap.parser import NmapParser

from automated_scans.nmap.host import Host
from automated_scans.nmap.services import Services


class NmapResults:

    def __init__(self):
        self.hosts = []

   # def get_nmap_results(self):
       # nmap_report = NmapParser.parse(nmap_proc.stdout)

      #  nmap_results = NmapResults()
       # nmap_results.add_hosts(nmap_report)

       # return nmap_results

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
