#!/usr/bin/env python

import sys
import json
import requests
from utils import *
import threading
import time


base_url = "http://localhost:5050"
headers = {'Content-Type': 'application/json'}

catalog_url = base_url + '/catalog'
list_vnfs_url = base_url + '/vnfs'
sfc_url = base_url + '/sfc'
sfc_uuid_url = sfc_url + '/uuid'
vnffg_compose_url = sfc_url + '/sfp/compose'
sfc_origin_url = sfc_url + '/acl/origin'
acl_url = sfc_url + '/acl'
start_sfc_url = sfc_url + '/start'


def compose_sfc(sfc_num):
    # CATALOG
    catalog = requests.get(catalog_url, headers=headers).json()['vnfs']
    # catalog = catalog['vnfs']
    # print(catalog[0])

    # SFC_UUID
    sfc_uuid = requests.get(sfc_uuid_url, headers=headers).json()['sfc_uuid']

    # VNF CHAINING
    vnf_data = {'sfc_uuid': sfc_uuid}

    for i in range(sfc_size):
        vnf_data['vnf_pkg_id'] = catalog[i]['_id']
        response = requests.post(vnffg_compose_url, headers=headers, data=json.dumps(vnf_data)).json()
        if response['status'] != OK:
            print(response['status'], response['reason'], sep=': ')
            sys.exit(1)

    # SFC TRAFFIC ORIGIN = EXTERNAL
    sfc_origin_data = {
        'origin': EXTERNAL,
        'sfc_uuid': sfc_uuid
    }

    # SFC TRAFFIC ORIGIN = INTERNAL
    # vnfs = requests.get(list_vnfs_url, headers=headers).json()['vnfs']
    # sfc_origin_data = {
    #     'origin': INTERNAL,
    #     'sfc_uuid': sfc_uuid,
    #     'vnf_id': vnfs[0]['vnf_id'],
    # }

    response = requests.post(sfc_origin_url, headers=headers, data=json.dumps(sfc_origin_data)).json()
    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        sys.exit(1)

    # ACL List
    _ = requests.get(acl_url, headers=headers).json()  # Just for simulate the request in a real scenario

    port = str(80 + sfc_num)
    acl_criteria = [
        {'ip_proto': 6},
        {'destination_port_range': '%s-%s' % (port, port)}
    ]
    acl_data = {
        'acl': acl_criteria,
        'sfc_uuid': sfc_uuid
    }

    # send ACL criteria to SFC_Core
    response = requests.post(acl_url, headers=headers, data=json.dumps(acl_data)).json()
    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        sys.exit(1)

    # start VNFFG
    response = requests.post(start_sfc_url, data=json.dumps({'sfc_uuid': sfc_uuid}), headers=headers).json()
    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        sys.exit(1)

    # end = time.time()
    # print("\nOK!", end - start)


if len(sys.argv) != 4:
    print("Usage: %s num_sfcs sfc_size rounds" % sys.argv[0])
    sys.exit(1)

num_sfcs = int(sys.argv[1])
sfc_size = int(sys.argv[2])
rounds = int(sys.argv[3])

for r in range(rounds):

    print("########## Round %s ##########" % r)

    total = 0.0

    for sfc in range(num_sfcs):
        start = time.time()
        compose_sfc(sfc)
        end = time.time()

        partial = end - start
        total += partial

        print("SFC %s\t%s" % (sfc, partial))

    print("TOTAL: %s\n\n" % total)

    # if r % 10 != 0:
    time.sleep(1)
    # else:
    #     time.sleep(1*60)
