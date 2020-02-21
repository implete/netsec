#!/usr/bin/env python
import nmap

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
                    creds = script['http-default-accounts'].replace('\n', '')
                    print([host,port,creds])


nma = nmap.PortScannerAsync()
nma.scan(
    hosts='-iL /tmp/ip.txt',
    arguments='-p 8080 -Pn -n --open --script=http-default-accounts',
    callback=callback_result
)

while nma.still_scanning():
    nma.wait(2)
