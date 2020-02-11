#!/usr/bin/env python3
import nmap
from builtins import list, filter

hosts = '10.10.10.*'

#### template code bellow ####

nse_scripts = ['banner', 'http-title']

ignore = [
    "Site doesn't have a title",
    'Requested resource was'
]


def not_ignored(result):
    return False if True in [i in result for i in ignore] else True


def has_script_results(script_name, script):
    if script_name in script and not_ignored(script[script_name]):
        return script_name + ':' + script[script_name]
    else:
        return None


def filter_none(array):
    return list(filter(None, array))


def callback_result(host, scan_result):
    scan = scan_result['scan']
    if scan:
        h = scan_result['scan'][host]
        if h['tcp']:
            for port in h['tcp']:
                product = h['tcp'][port]['product'] if 'product' in h['tcp'][port] else None
                script_results = []
                if 'script' in h['tcp'][port]:
                    script = h['tcp'][port]['script']
                    script_results = filter_none([has_script_results(x, script) for x in nse_scripts])

                print(filter_none([host, port, script_results, product]))


nma = nmap.PortScannerAsync()
nma.scan(
    hosts=hosts,
    arguments='--open -p443,80 -sT -T4 -Pn -n -sV -sC --script="' + ','.join(x for x in nse_scripts) + '"',
    callback=callback_result
)
while nma.still_scanning():
    nma.wait(2)
