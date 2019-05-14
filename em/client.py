import requests
import json
import os
import sys

VXLAN_PATH = '/home/gvsouza/Desktop/vxlan.sh'
IPSEC_PATH = '/home/gvsouza/Desktop/ipsec.sh'

url = 'http://0.0.0.0:9000/em/install'

if len(sys.argv) != 2:
    print "Usage: %s [vxlan|ipsec]" % sys.argv[0]
    exit(1)

type = sys.argv[1]

if type == 'ipsec':
    script_path = IPSEC_PATH
    args = {
        'type': type,
        'local_ip': '172.24.240.7',
        'remote_ip': '172.24.241.10',
        'local_lan': '10.10.0.0/24',
        'remote_lan': '10.10.1.0/24'
    }

elif type == 'vxlan':
    script_path = VXLAN_PATH
    args = {
        'type': type,
        'action': 'start',
        'local_ip': '172.24.241.10',
        'remote_ip': '172.24.240.12',
        'iface': 'ens5',
        'id': '100',
        'vxlan_local_ip': '192.168.200.1/24',
        'vxlan_remote_ip': '192.168.200.2',
        'route_net_host': '10.10.1.11/32',
        'arp_proxy_remote_host': '10.10.1.11',
        'arp_proxy_iface': 'ens4'
    }

files = {
    'json': (None, json.dumps(args), 'application/json'),
    'file': (os.path.basename(script_path), open(script_path, 'rb'), 'application/octet-stream')
}

response = requests.post(url, files=files)

print response
print response.json()
