#!/usr/bin/python

import requests
import subprocess
import sys

BEARER = "hunter2"
URL = "https://example.com/ipset"
IPSET = "hpcuafw"

if __name__ == "__main__":
    ipsetd = subprocess.Popen(['/usr/sbin/ipset', '-'], stdin=subprocess.PIPE)

    ipsetd.stdin.write("create -exist %s hash:net family inet timeout 300\n" % IPSET)
    ipsetd.stdin.write("create -exist %s-6 hash:net family inet6 timeout 300\n" % IPSET)

    index = 0
    while True:
        response = requests.get(URL, params={'index': index}, headers={'Authorization': BEARER})

        if response.status_code != 200:
            print('Could not fetch url')
            sys.exit(1)

        if 'X-Last-Index' in response.headers:
            index = response.headers['X-Last-Index']

        records = response.json()

        print('Received %d records' % len(records))

        for record in records:
            if ':' in record['ip']:
                ipsetd.stdin.write("add -exist %s-6 %s timeout %d\n" % (IPSET, record['ip'], record['timeout']))
            else:
                ipsetd.stdin.write("add -exist %s %s timeout %d\n" % (IPSET, record['ip'], record['timeout']))
