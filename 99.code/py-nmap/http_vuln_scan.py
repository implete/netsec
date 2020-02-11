#!/usr/bin/env python3
import nmap
import sys


def usage():
    print('Usage: python ' + sys.argv[0] + ' <IP>:<port1,port2,...>')
    sys.exit(1)


if (len(sys.argv) != 2):
    usage()

try:
    ip = sys.argv[1].split(':')[0]
    port = sys.argv[1].split(':')[1]
except IndexError as e:
    usage()

nse_scripts = ','.join([
    'http-vuln-*',
    'http-shellshock',
    'ssl-heartbleed'
])

nm = nmap.PortScanner()
nm.scan(
    hosts=ip,
    arguments='-p ' + port + ' -sT -Pn -n' + ' --script="' + nse_scripts + '"',
    sudo=True
)

for host in nm.analyse_nmap_xml_scan()['scan']:
    if nm[host]['status']['state'] == 'up':
        for port in nm[host]['tcp']:
            if 'script' in nm[host]['tcp'][port]:
                for script_name in nm[host]['tcp'][port]['script']:
                    data = nm[host]['tcp'][port]['script'][script_name]
                    if 'VULNERABLE' in data:
                        print(script_name, host, port)
