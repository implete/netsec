#!/usr/bin/env python3
import nmap

ip = '192.168.1.1'
ports = '0-65535'

nm = nmap.PortScanner()
nm.scan(hosts=ip, arguments='--open -sS -Pn -n -p ' + ports)

for host in nm.analyse_nmap_xml_scan()['scan']:
    open_ports = list()
    if nm[host]['status']['state'] == 'up':
        for port in nm[host]['tcp']:
            open_ports.append(str(port) + '/' + nm[host]['tcp'][port]['name'])
    print(host + ': ' + ','.join(open_ports))
