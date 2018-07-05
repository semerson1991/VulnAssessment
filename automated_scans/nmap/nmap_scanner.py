#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from automated_scans.nmap.nmap_results import NmapResult


class NmapScanner:
    def __init__(self):
        pass

    def run_nmap_scan(self, targets):
        #nmap_proc = NmapProcess(targets="10.10.10.0/24", options="-A") # "-sS -A -v")
        nmap_proc = NmapProcess(targets=targets, options="-O")  # "-sS -A -v")
        nmap_proc.run_background()

        while nmap_proc.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
                                                                  nmap_proc.progress))
        sleep(7)

        nmap_report = NmapParser.parse(nmap_proc.stdout)

        nmap_result = NmapResult()
        nmap_result.add_hosts(nmap_report)
        return nmap_result


if __name__ == "__main__":
    nmap = NmapScanner
    nmap.run_nmap_scan(nmap)