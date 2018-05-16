#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from automated_scans.nmap.nmap_results import NmapResults


class NmapScanner:

    def run_nmap_scan(self):
        parsed = None
        nmap_proc = NmapProcess(targets="10.10.10.3", options="")
        nmap_proc.run_background()

        while nmap_proc.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
                                                                  nmap_proc.progress))
        sleep(2)

        nmap_report = NmapParser.parse(nmap_proc.stdout)

        nmap_results = NmapResults()
        nmap_results.add_hosts(nmap_report)
        return nmap_results


if __name__ == "__main__":
    nmap = NmapScanner
    nmap.run_nmap_scan(nmap)