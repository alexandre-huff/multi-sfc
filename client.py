#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import requests
from prettytable import PrettyTable
from utils import *

base_url = "http://localhost:5050"
headers = {'Content-Type': 'application/json'}


def validate_vnfp(path):
    vnfd_file = get_vnfd_file_name(path)
    if not vnfd_file:
        return 0

    path = ''.join([os.getcwd(), '/', path])

    if not os.path.exists(path)                  or \
        not os.path.isfile(vnfd_file)            or \
            not os.path.isfile(path + '/descriptor.json'):
        return 0

    with open(path + '/descriptor.json', 'r') as desc_file:
        descriptor = desc_file.read()

    descriptor = json.loads(descriptor)
    if descriptor['type'] == CLICK_VNF:
        if not os.path.isfile(path + '/vnf.click'):
            return 0

    return 1


def get_vnfd_file_name(path):
    path = ''.join([os.getcwd(), '/', path])

    json_file = path + '/vnfd.json'
    yaml_file = path + '/vnfd.yaml'

    if os.path.isfile(json_file):
        return json_file
    elif os.path.isfile(yaml_file):
        return yaml_file
    else:
        return None


def include_package():
    # TODO: also include a VNF Package with YAML descriptors (needs to parse YAML to JSON)

    vnf_package_path = input("VNF Package path: ")
    # vnf_package_path = "example/vnfp6"

    if not validate_vnfp(vnf_package_path):
        print("Invalid VNF Package!")
        return 0

    vnfd = open(get_vnfd_file_name(vnf_package_path), 'r').read()
    descriptor = open(vnf_package_path + '/descriptor.json', 'r').read()

    vnf_package = {
        'vnfd': vnfd,
        'descriptor': descriptor
    }

    vnf_type = json.loads(descriptor)['type']
    if vnf_type == CLICK_VNF:
        vnf_function = open(vnf_package_path + '/vnf.click', 'r').read()
        vnf_package['vnf'] = vnf_function

    url = base_url + '/package'

    response = requests.post(url, data=json.dumps(vnf_package), headers=headers).json()

    if response['status'] == OK:
        print("VNF Package included!")
    else:
        print(response['status'], response['reason'], sep='! ')


def remove_package():
    catalog = list_catalog()
    if not catalog:
        return

    print("Choose a VNF Package to remove from the VNF Catalog or 0 to exit.")
    seq = int(input("SEQ > "))

    if seq <= 0:
        return

    try:
        vnf_package_id = catalog[seq - 1]['_id']
    except IndexError:
        print("Invalid SEQ number!")
        return

    # send vnf_package_id as the first element of the list indexed with the SEQ-1 chosen by user
    url = base_url + '/package/' + vnf_package_id
    response = requests.delete(url, headers=headers)

    if response.json()['status'] == OK:
        print("VNF Package removed!")
    else:
        print("VNF Package not removed! %s" % response.json()['reason'])


def list_catalog():
    url = base_url + '/catalog'
    catalog = requests.get(url, headers=headers).json()
    catalog = catalog['vnfs']

    if not catalog:
        print("\nNo VNF available!")
    else:
        # Currently, the VNF Catalog column shows each VNF category stored in catalog
        table = PrettyTable(["SEQ", "VNF Category", "Description", "Platform"])

        index = 0
        for vnf in catalog:
            index += 1
            row = [index, vnf['category'], vnf['description'], vnf['platform']]
            table.add_row(row)

        print(table)

    return catalog


def instantiate_vnf():
    url = base_url + '/vnfs/'

    catalog = list_catalog()
    if not catalog:
        return

    print("\nChoose a VNF to instantiate by their Catalog SEQ, or 0 to exit")
    seq = int(input("\nSEQ > "))

    if seq <= 0:
        return
    try:
        vnf_pkg_id = catalog[seq - 1]['_id']
    except IndexError:
        print("Invalid SEQ number!")
        return

    response = requests.post(url + vnf_pkg_id, headers=headers).json()

    if response['status'] == OK:
        print("VNF instantiated successfully!")
    else:
        print(response['status'], response['reason'], sep=': ')


def destroy_vnf():
    url = base_url + '/vnfs/'

    vnfs = list_vnfs()
    if not vnfs:
        return

    print("Choose a VNF to destroy or 0 to exit.")
    seq = int(input("SEQ > "))
    if seq <= 0:
        return

    try:
        vnf_id = vnfs[seq - 1]['vnf_id']
    except IndexError:
        print("Invalid SEQ number!")
        return

    # send vnf_id as the first element of the list indexed with the SEQ-1 chosen by user
    response = requests.delete(url + vnf_id, headers=headers).json()

    if response['status'] == OK:
        print("VNF destroyed successfully!")
    else:
        print("VNF not destroyed! %s" % response['reason'])


def list_vnfs():
    url = base_url + '/vnfs'
    response = requests.get(url, headers=headers).json()
    # print(json.dumps(vnfs, indent=2))

    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    vnfs = response['vnfs']

    if vnfs:
        table = PrettyTable(["SEQ", "VNF Name", "Instance Name", "Mgmt Address", "Status"])

        index = 0
        for vnf in vnfs:
            index += 1
            row = [index, vnf['vnf_name'], vnf['instance_name'], vnf['mgmt_url'], vnf['vnf_status']]
            table.add_row(row)

        print(table)
    else:
        print("\nNo VNF instantiated in NVFO!")

    return vnfs


def create_sfc_v2():
    sfc_url = base_url + '/sfc'
    sfc_uuid_url = sfc_url + '/uuid'
    vnffg_compose_url = sfc_url + '/sfp/compose'
    sfc_origin_url = sfc_url + '/acl/origin'
    acl_url = sfc_url + '/acl'

    catalog = list_catalog()
    if not catalog:
        return

    sfc_uuid = requests.get(sfc_uuid_url, headers=headers).json()['sfc_uuid']

    print("\nAdd VNFs by their Catalog SEQ (0 for done, or -1 to exit)")

    vnf_data = {'sfc_uuid': sfc_uuid}
    while True:
        seq = int(input("\nSEQ > "))

        if seq == 0:
            break
        if seq < 0:
            return
        try:
            vnf_pkg_id = catalog[seq - 1]['_id']
        except IndexError:
            print("Invalid SEQ number!")
            return

        vnf_data['vnf_pkg_id'] = vnf_pkg_id

        while True:
            response = requests.post(vnffg_compose_url, headers=headers, data=json.dumps(vnf_data)).json()

            if response['status'] == OK:
                print("VNF included successfully!")
                break

            elif response['status'] == OPTIONS:
                print(response['reason'])
                cps = sorted(response['cp_list'])
                for cp in cps:
                    print('%s: %s' % (cp, response['cp_list'][cp]['network_name']))

                vnf_data['cp_out'] = input("\nOutput CP > ")

                continue

            else:
                print(response['status'], response['reason'], sep=': ')
                break

    print("\nIncoming SFC Network Traffic?\n%s. Internal\n%s. External" % (INTERNAL, EXTERNAL))
    while True:
        origin = input("> ")
        if origin in [INTERNAL, EXTERNAL]:
            break
        else:
            print("Invalid Option!")

    if origin == INTERNAL:
        nfvo_vnfs = list_vnfs()
        # print(nfvo_vnfs)

        if not nfvo_vnfs:
            return

        print("\nChoose a VNF that generates the incoming SFC traffic, or 0 to exit")
        vnf_origin = int(input("SEQ > "))

        if vnf_origin <= 0:
            return
        try:
            vnf_id = nfvo_vnfs[vnf_origin - 1]['vnf_id']
        except IndexError:
            print("Invalid SEQ number!")
            return

        sfc_origin_data = {
            'origin': origin,
            'vnf_id': vnf_id,
            'sfc_uuid': sfc_uuid
        }

        while True:
            response = requests.post(sfc_origin_url, headers=headers, data=json.dumps(sfc_origin_data)).json()

            if response['status'] == OK:
                break

            elif response['status'] == OPTIONS:
                vnf_pkg_cps = response['cp_list']
                cps = sorted(vnf_pkg_cps)
                for cp in cps:
                    print('%s: %s' % (cp, vnf_pkg_cps[cp]['network_name']))

                cp_output = input("Output CP > ")
                sfc_origin_data['resource'] = cp_output

            else:
                print(response['status'], response['reason'], sep=': ')
                return

    else:  # if origin == EXTERNAL
        sfc_origin_data = {
            'origin': origin,
            'sfc_uuid': sfc_uuid
        }
        response = requests.post(sfc_origin_url, headers=headers, data=json.dumps(sfc_origin_data)).json()

        if response['status'] != OK:
            print(response['status'], response['reason'], sep=': ')
            return

    # ACL List
    response = requests.get(acl_url, headers=headers).json()
    acl_list = response['acl']

    table = PrettyTable(['ID', 'Description'], sortby='ID')

    for acl_id, desc in acl_list.items():
        table.add_row([acl_id, desc])

    print(table)

    print("\nAdd the criteria by their respective ID (0 for done, or -1 to exit)")

    acl = []
    while True:
        acl_criteria = input('ID > ')

        if acl_criteria == "0":
            break

        if acl_criteria == "-1":
            return

        if acl_criteria not in acl_list.keys():
            print("Invalid Criteria!")
            continue

        acl_value = input('Value > ')

        acl.append({
            acl_criteria: acl_value
        })

    acl_data = {
        'acl': acl,
        'sfc_uuid': sfc_uuid
    }

    # send ACL criteria to SFC_Core
    response = requests.post(acl_url, headers=headers, data=json.dumps(acl_data)).json()

    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    # start VNFFG
    response = requests.post(sfc_url + '/start', data=json.dumps({'sfc_uuid': sfc_uuid}), headers=headers).json()
    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    print("VNFFG instantiated successfully!")


def list_sfcs():
    url = base_url + '/sfc'
    response = requests.get(url, headers=headers).json()

    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    vnffgs = response['vnffgs']
    if vnffgs:
        table = PrettyTable(["SEQ", "VNFFG Name", "Status", "VNF Chain", "Description"])

        index = 0
        for vnffg in vnffgs:
            index += 1
            row = [index, vnffg['name'], vnffg['status'], ' -> '.join(vnffg['vnf_chain']), vnffg['description']]
            table.add_row(row)

        print(table)
    else:
        print("\nNo VNFFG instantiated in NVFO!")

    return vnffgs


def destroy_sfc():
    sfcs = list_sfcs()
    if not sfcs:
        return

    print("Choose a SFC to destroy or 0 to exit.")
    seq = int(input("SEQ > "))
    if seq <= 0:
        return

    try:
        vnffg_id = sfcs[seq - 1]['id']
    except IndexError:
        print("Invalid SEQ number!")
        return

    url = base_url + '/sfc/' + vnffg_id
    response = requests.delete(url, headers=headers).json()

    if response['status'] == OK:
        print("SFC destroyed successfully!")
    else:
        print("SFC not destroyed! %s" % response['reason'])


while True:
    print("\n1. Include VNF Package")
    print("2. Remove VNF Package")
    print("3. Show VNF Catalog")
    print("4. Instantiate VNF")
    print("5. Destroy VNF Instance")
    print("6. Show VNF Instances")
    print("7. Compose SFC")
    print("8. Destroy SFC")
    print("9. Show SFC Instances")
    print("0. Exit")

    option = input("\n> ")

    if option == "1":
        include_package()
    elif option == "2":
        remove_package()
    elif option == "3":
        list_catalog()
    elif option == "4":
        instantiate_vnf()
    elif option == "5":
        destroy_vnf()
    elif option == "6":
        list_vnfs()
    elif option == "7":
        create_sfc_v2()
    elif option == "8":
        destroy_sfc()
    elif option == "9":
        list_sfcs()
    elif option == "0":
        break
    else:
        print("Invalid Option")
