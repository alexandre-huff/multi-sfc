#!/usr/bin/env python

import requests
import json
import os
import sys

VXLAN_PATH = 'em/vxlan.sh'
IPSEC_PATH = 'em/ipsec.sh'

url = 'http://192.168.241.15:8000/em/config'

if len(sys.argv) != 2:
    print("Usage: %s [vxlan|ipsec]" % sys.argv[0])
    exit(1)

tunnel = sys.argv[1]

if tunnel == 'ipsec':
    script_path = IPSEC_PATH
    args = {
        'type': tunnel,
        'local_ip': '172.24.240.7',
        'remote_ip': '172.24.241.10',
        'local_lan': '10.10.0.0/24',
        'remote_lan': '10.10.1.0/24'
    }

elif tunnel == 'vxlan':
    script_path = VXLAN_PATH
    args = {
        'type': tunnel,
        'action': 'start',
        'local_ip': '172.24.241.24',
        'remote_ip': '172.24.240.3',
        'vxlan_local_ip': '192.168.200.1/30',
        'vxlan_remote_ip': '192.168.200.2',
        'route_net_host': '10.0.0.0/24',
        'nat': 'False'
    }

else:
    raise NotImplementedError("Unknown '%s' type" % tunnel)

files = {
    'json': (None, json.dumps(args), 'application/json'),
    'file': (os.path.basename(script_path), open('/'.join([os.getcwd(), script_path]), 'rb'), 'application/octet-stream')
}

response = requests.post(url, files=files)

print(response)
print(response.json())
