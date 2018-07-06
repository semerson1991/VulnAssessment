#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from automated_scans.nmap.nmap_results import NmapResult


class NmapScanner:
    def __init__(self):
        pass

    def run_nmap_scan(self, targets, scan_id):
        #nmap_proc = NmapProcess(targets="10.10.10.0/24", options="-A") # "-sS -A -v")
        nmap_proc = NmapProcess(targets=targets, options="-O")  # "-sS -A -v")
        nmap_proc.run_background()

        while nmap_proc.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
                                                                  nmap_proc.progress))
        sleep(7)

        #Store in file
        file_path = "/root/Desktop/FinalYearProjectRESTAPI/automated_scans/reports/"+str(scan_id)+".xml"
        file = open(file_path, "w")
        data = nmap_proc.stdout
        file.write(data)
        file.close()

        print(data)
        print(type(data))

        return file_path


if __name__ == "__main__":
    nmap = NmapScanner
    nmap.run_nmap_scan(nmap)