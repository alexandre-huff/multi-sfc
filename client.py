#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import requests
import base64
import yaml
from prettytable import PrettyTable
from utils import *

base_url = "http://localhost:5050"
headers = {'Content-Type': 'application/json'}


def validate_vnfp(path):
    vnfd_file = get_vnfd_file_name(path)
    if not vnfd_file:
        return False

    pkg_name = path
    path = ''.join([os.getcwd(), '/', path])

    if not os.path.exists(path)                  or \
        not os.path.isfile(vnfd_file)            or \
            not os.path.isfile(path + '/descriptor.json'):
        return False

    with open(path + '/descriptor.json', 'r') as desc_file:
        descriptor = desc_file.read()

    descriptor = json.loads(descriptor)

    if descriptor['platform'] == OSM_NFVO:
        if not os.path.isfile(get_nsd_file_name(pkg_name)):
            return False

    if descriptor['type'] == CLICK_VNF:
        if not os.path.isfile(path + '/vnf.click'):
            return False

    return True


def get_vnfd_file_name(path):
    path = ''.join([os.getcwd(), '/', path])

    json_file = path + '/vnfd.json'
    yaml_file = path + '/vnfd.yaml'

    try:
        files = os.listdir(path)
    except FileNotFoundError:
        return None

    osm_vnfd = [f for f in files if 'vnf.tar.gz' in f]
    if len(osm_vnfd) > 0:
        osm_vnfd = path + '/' + osm_vnfd[0]
    else:
        osm_vnfd = ''

    if os.path.isfile(json_file):
        return json_file
    elif os.path.isfile(yaml_file):
        return yaml_file
    elif os.path.isfile(osm_vnfd):
        return osm_vnfd
    else:
        return None


def get_nsd_file_name(path):
    path = ''.join([os.getcwd(), '/', path])
    files = os.listdir(path)
    osm_nsd = [f for f in files if 'ns.tar.gz' in f]
    if len(osm_nsd) > 0:
        osm_nsd = path + '/' + osm_nsd[0]
        return osm_nsd
    else:
        return ''


def include_package():
    url = base_url + '/package'

    table = PrettyTable(["VNF Package", "Description", "Platform", "VNF Category"])

    package_dir = 'example/'
    dirs = os.listdir(package_dir)
    # dirs.sort()

    for dir in dirs:
        with open(package_dir + '/' + dir + '/descriptor.json', 'r') as descriptor:
            vnfp = json.loads(descriptor.read())
            row = [dir, vnfp['description'], vnfp['platform'], vnfp['category']]
            table.add_row(row)

    table.sortby = "Description"
    # print(table.get_string(sort_key=operator.itemgetter(1, 0), sortby="Grade"))
    print(table)

    vnf_package_path = input("VNF Package: ")
    # vnf_package_path = "osm-vnfp2"
    vnf_package_path = ''.join([package_dir, vnf_package_path])

    if not validate_vnfp(vnf_package_path):
        print("Invalid VNF Package!")
        return

    with open(vnf_package_path + '/descriptor.json', 'r') as f:
        descriptor = f.read()

    platform = json.loads(descriptor)['platform']
    vnfd_file = get_vnfd_file_name(vnf_package_path)

    vnf_package = {
        'descriptor': descriptor
    }

    vnf_type = json.loads(descriptor)['type']
    if vnf_type == CLICK_VNF:
        with open(vnf_package_path + '/vnf.click', 'r') as f:
            vnf_function = f.read()
        vnf_package['vnf'] = vnf_function

    if platform == TACKER_NFVO:
        with open(vnfd_file, 'r') as f:
            vnfd = f.read()
        vnf_package['vnfd'] = vnfd

    elif platform == OSM_NFVO:
        with open(vnfd_file, 'rb') as f:
            vnfd = f.read()
        vnfd_bytes = base64.b64encode(vnfd)
        vnfd_str = vnfd_bytes.decode('utf-8')
        vnf_package['vnfd'] = vnfd_str

        nsd_file = get_nsd_file_name(vnf_package_path)
        with open(nsd_file, 'rb') as f:
            nsd = f.read()
        nsd_bytes = base64.b64encode(nsd)
        nsd_str = nsd_bytes.decode('utf-8')
        vnf_package['nsd'] = nsd_str

    else:
        return

    while True:
        response = requests.post(url, data=json.dumps(vnf_package), headers=headers).json()

        if response['status'] == OPTIONS:
            print("\n", response['reason'], "\n", sep='')

            domain_data = response['domain_data']
            table = PrettyTable(["SEQ", "Domain"])
            index = 0
            row = [0, ANY]
            table.add_row(row)
            for item in domain_data['domains']:
                index += 1
                row = [index, item['domain_name']]
                table.add_row(row)

            print(table)
            print("Select a domain (-1 to exit)")

            while True:
                domain_seq = int(input("SEQ > "))

                if domain_seq < 0:
                    return
                elif domain_seq == 0:
                    domain_id = ANY
                    nfvo_id = ANY
                else:
                    try:
                        domain_id = domain_data['domains'][domain_seq - 1]['domain_id']
                        domain_name = domain_data['domains'][domain_seq - 1]['domain_name']
                    except IndexError:
                        print("Invalid SEQ number!")
                        continue

                    table = PrettyTable(["SEQ", "Platform Instance"])
                    index = 0
                    row = [0, ANY]
                    table.add_row(row)
                    domains = [domain for domain in domain_data['domains'] if domain['domain_id'] == domain_id]
                    for domain in domains:
                        for item in domain['nfvos']:
                            index += 1
                            row = [index, item['nfvo_name']]
                            table.add_row(row)

                    print(table)
                    print("Select a Platform Instance in '%s' (-1 to exit)" % domain_name)

                    while True:
                        nfvo_seq = int(input("SEQ > "))

                        if nfvo_seq < 0:
                            return
                        elif nfvo_seq == 0:
                            nfvo_id = ANY
                        else:
                            try:
                                nfvo_id = domain_data['domains'][domain_seq - 1]['nfvos'][nfvo_seq - 1]['nfvo_id']
                            except IndexError:
                                print("Invalid SEQ number!")
                                continue
                        break

                break
            vnf_package.update({
                'domain_id': domain_id,
                'nfvo_id': nfvo_id
            })

        elif response['status'] == OK:
            print("VNF Package included!")
            break
        else:
            print(response['status'], response['reason'], sep='! ')
            break


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
    url = base_url + '/catalog/vnfs'
    catalog = requests.get(url, headers=headers).json()
    catalog = catalog['vnfs']

    if not catalog:
        print("\nThere is no VNF package!")
    else:
        table = PrettyTable(["SEQ", "VNF Category", "VNF Description", "Platform", "Domain", "Platform Instance"])

        index = 0
        for vnf in catalog:
            index += 1
            row = [index, vnf['category'], vnf['description'], vnf['platform'], vnf['domain_name'], vnf['nfvo_name']]
            table.add_row(row)

        print(table)

    return catalog


def create_vnf():
    url = base_url + '/vnfs'

    catalog = list_catalog()
    if not catalog:
        return

    print("\nChoose a VNF to instantiate by their Catalog SEQ, or 0 to exit")
    seq = int(input("\nSEQ > "))

    if seq <= 0:
        return
    try:
        vnfp_data = {'vnfp_id': catalog[seq - 1]['_id']}
    except IndexError:
        print("Invalid SEQ number!")
        return

    while True:
        response = requests.post(url, data=json.dumps(vnfp_data), headers=headers).json()

        if response['status'] == OPTIONS:
            print("\n", response['reason'], "\n", sep='')

            domain_data = select_domain_nfvo_ids(response['domain_data'])
            if not domain_data:
                return

            vnfp_data.update(domain_data)

        elif response['status'] == OK:
            print("VNF instantiated successfully!")
            break

        else:
            print(response['status'], response['reason'], sep=': ')
            break


def select_domain_nfvo_ids(domain_data):
    """Allows the user to select a domain id and nfvo id

    :param domain_data: contains a dict with a list of domains, each containing a list of nfvos
    :return: a dict with domain_id and nfvo_id, or None if nothing was selected
    """
    domains = domain_data['domains']
    header = ["Domain"]
    rows = []
    if len(domains) > 1:
        for domain in domains:
            rows.append([domain['domain_name']])

        index = select_pretty_table_item(header, rows, "Select a Domain")
        if index is None:
            return None

        domain_id = domains[index]['domain_id']

    else:
        domain_id = domains[0]['domain_id']
        index = 0

    header = ["Platform Instance"]
    rows = []
    nfvos = domains[index]['nfvos']
    for nfvo in nfvos:
        rows.append([nfvo['nfvo_name']])

    nfvo_index = select_pretty_table_item(header, rows, "Select a Platform Instance")
    if nfvo_index is None:
        return None

    nfvo_id = nfvos[nfvo_index]['nfvo_id']

    return {
        'domain_id': domain_id,
        'nfvo_id': nfvo_id
    }


def select_pretty_table_item(header, rows, msg, returned_field="SEQ"):
    """Generic function to print and choose data

    :param header: a list with header field names
    :param rows: a list containing another list with field values
    :param msg: a message to show to the user
    :param returned_field: the name of the field to be returned
    :return: the value of the selected field, or None if nothing was selected
    """
    header.insert(0, "SEQ")
    field_index = header.index(returned_field)

    table = PrettyTable(header)
    index = 0
    for row in rows:
        index += 1
        row.insert(0, index)
        table.add_row(row)

    print("\n", table, sep='')
    print(msg, "(-1 to exit)")

    while True:
        seq = int(input("SEQ > "))

        if seq == 0:
            print("Invalid SEQ number!")
            continue
        elif seq < 0:
            return None

        try:
            data = rows[seq - 1][field_index]
            break
        except IndexError:
            print("Invalid SEQ number!")
            continue

    if returned_field == "SEQ":
        return data - 1
    else:
        return data


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
        table = PrettyTable(["SEQ", "VNF ID", "VNF Name", "Mgmt Address", "Status", "Platform",
                             "Domain", "Platform Instance", "Platform VIM"])

        index = 0
        for vnf in vnfs:
            index += 1
            row = [index, vnf['vnf_id'], vnf['vnf_name'], vnf['mgmt_url'], vnf['vnf_status'], vnf['platform'],
                   vnf['domain_name'], vnf['nfvo_name'], vnf['vim_name']]
            table.add_row(row)

        print(table)
    else:
        print("\nThere is no VNF instance!")

    return vnfs


def create_sfc():
    catalog_url = base_url + '/catalog/vnfs'
    sfc_url = base_url + '/sfc'
    sfc_uuid_url = sfc_url + '/uuid'
    vnffg_compose_url = sfc_url + '/sfp/compose'
    sfc_origin_url = sfc_url + '/acl/origin'
    acl_url = sfc_url + '/acl'
    domain_url = base_url + '/catalog/domains'

    sfc_uuid = requests.get(sfc_uuid_url, headers=headers).json()['sfc_uuid']

    domain_catalog = requests.get(domain_url, headers=headers).json()

    while True:
        header = ["Domain", "Platform Instance", "Project", "VIM Name", "Tunnel"]
        rows = []
        for item in domain_catalog:
            row = [item['domain_name'], item['nfvo_name'], item['tenant_name'], item['vim_name'], item['tunnel']]
            rows.append(row)

        domain_seq = select_pretty_table_item(header, rows, "Select a domain/platform to compose this SFC segment")
        if domain_seq is None:
            return

        domain_id = domain_catalog[domain_seq]['domain_id']
        nfvo_id = domain_catalog[domain_seq]['nfvo_id']

        catalog = requests.get(catalog_url + '/%s/%s' % (domain_id, nfvo_id), headers=headers).json()['vnfs']
        if not catalog:
            return

        table = PrettyTable(["SEQ", "VNF Category", "VNF Description", "Platform", "Domain", "Platform Instance"])
        index = 0
        for vnf in catalog:
            index += 1
            row = [index, vnf['category'], vnf['description'], vnf['platform'], vnf['domain_name'], vnf['nfvo_name']]
            table.add_row(row)

        print("\n", table, sep='')

        print("Add VNFs by their Catalog SEQ (0 for done, or -1 to exit)")

        while True:
            seq = int(input("SEQ > "))

            if seq == 0:
                break
            if seq < 0:
                return
            try:
                vnf_pkg_id = catalog[seq - 1]['_id']
            except IndexError:
                print("Invalid SEQ number!")
                return

            vnf_data = {
                'sfc_uuid': sfc_uuid,
                'vnf_pkg_id': vnf_pkg_id,
                'domain_id': domain_id,
                'nfvo_id': nfvo_id
            }

            while True:
                response = requests.post(vnffg_compose_url, headers=headers, data=json.dumps(vnf_data)).json()

                if response['status'] == OK:
                    print("VNF included successfully!")
                    break

                elif response['status'] == OPTIONS:
                    print("\n", response['reason'], sep='')

                    cps = sorted(response['cp_list'])
                    for cp in cps:
                        print('%s: %s' % (cp, response['cp_list'][cp]['network_name']))

                    vnf_data['cp_out'] = input("\nOutput CP > ")

                    continue

                else:
                    print(response['status'], response['reason'], sep=': ')
                    break

        print("\nAdd more SFC segments? (-1 to exit)\n1. Yes\n2. No")
        while True:
            op = int(input("> "))
            if op not in (-1, 1, 2):
                print("Invalid option!")
                continue
            break

        if op == -1:
            return
        if op == 2:
            break

    print("\nSource of SFC network traffic at the first segment\n%s. Internal\n%s. External" % (INTERNAL, EXTERNAL))
    while True:
        origin = input("> ")
        if origin in [INTERNAL, EXTERNAL]:
            break
        else:
            print("Invalid Option!")

    sfc_origin_data = {
        'sfc_uuid': sfc_uuid,
        'origin': origin
    }

    if origin == INTERNAL:
        nfvo_vnfs = requests.get(sfc_origin_url + '/%s' % sfc_uuid, headers=headers).json()
        # nfvo_vnfs = requests.get('/'.join([sfc_origin_url, platform]), headers=headers).json()
        # print(nfvo_vnfs)

        if nfvo_vnfs['status'] != OK:
            print(nfvo_vnfs['status'], nfvo_vnfs['reason'], sep=': ')
            return

        if not nfvo_vnfs.get('vnfs'):
            print("No available VNF to generate SFC incoming traffic!")
            return

        fields = nfvo_vnfs.get('fields')
        t_head = []
        for field in fields:
            t_head.append(list(field.values())[0])

        rows = []
        for vnf in nfvo_vnfs.get('vnfs'):
            row = []
            for field in fields:
                k = [*field][0]
                row.append(vnf[k])
            rows.append(row)

        msg = "Choose a VNF to generate the SFC incoming traffic for the first segment"
        seq = select_pretty_table_item(t_head, rows, msg)
        if seq is None:
            return

        while True:

            src_id = nfvo_vnfs['vnfs'][seq]['id']
            sfc_origin_data['src_id'] = src_id

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
                while True:
                    seq = int(input("SEQ > "))
                    if seq < 0:
                        return
                    if seq == 0 or seq > len(rows):
                        print("Invalid SEQ number!")
                        continue
                    break
                # adjusting to the correct index
                seq -= 1

    else:  # if origin == EXTERNAL
        response = requests.post(sfc_origin_url, headers=headers, data=json.dumps(sfc_origin_data)).json()

        if response['status'] != OK:
            print(response['status'], response['reason'], sep=': ')
            return

    # ACL List
    response = requests.get(acl_url + '/%s' % sfc_uuid, headers=headers).json()
    try:
        acl_list = response['acl']
    except KeyError:
        print(response['status'], response['reason'], sep=': ')
        return

    table = PrettyTable(['ID', 'Description'], sortby='ID')

    for acl_id, desc in acl_list.items():
        table.add_row([acl_id, desc])

    print("\n", table, sep="")

    print("Add the criteria by their respective ID (0 for done, or -1 to exit)")

    acl = {}
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

        acl[acl_criteria] = acl_value

    acl_data = {
        'acl': acl,
        'sfc_uuid': sfc_uuid
    }

    # send ACL criteria to SFC_Core
    response = requests.post(acl_url, headers=headers, data=json.dumps(acl_data)).json()

    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    print("\nAdd a name for this SFC (optional)")
    sfc_name = input("Name > ")
    sfc_data = {
        'sfc_uuid': sfc_uuid,
        'sfc_name': sfc_name
    }

    # start SFCs
    response = requests.post(sfc_url + '/start', data=json.dumps(sfc_data), headers=headers).json()
    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    print("SFC instantiated successfully!")


def list_sfcs():
    url = base_url + '/sfc'
    response = requests.get(url, headers=headers).json()

    if response['status'] != OK:
        print(response['status'], response['reason'], sep=': ')
        return

    sfcs = response['sfcs']
    if sfcs:
        table = PrettyTable(["SEQ", "Multi-SFC", "Segment Name", "Status", "Domain", "Platform",
                             "Platform Instance", "Service Function Path", "Policy"])

        index = 0
        for sfc in sfcs:
            index += 1
            row = [index, sfc['multi_sfc_id'], sfc['name'], sfc['status'], sfc['domain_name'], sfc['platform'],
                   sfc['nfvo_name'], '\n'.join(sfc['vnf_chain']) + '\n', yaml.safe_dump(sfc['policy'])]
            table.add_row(row)

        print(table)
    else:
        print("\nThere is no SFC instance!")

    return sfcs


def destroy_sfc():
    sfcs = list_sfcs()
    if not sfcs:
        return

    print("Choose a Multi-SFC to destroy or 0 to exit.")
    seq = int(input("SEQ > "))
    if seq <= 0:
        return

    try:
        vnffg_id = sfcs[seq - 1]['multi_sfc_id']
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
        create_vnf()
    elif option == "5":
        destroy_vnf()
    elif option == "6":
        list_vnfs()
    elif option == "7":
        create_sfc()
    elif option == "8":
        destroy_sfc()
    elif option == "9":
        list_sfcs()
    elif option == "0":
        break
    else:
        print("Invalid Option")
