#!/usr/bin/env python

import logging
import json
import yaml
import os
import time
import base64
import tarfile
from multiprocessing.pool import Pool

from utils import *
from flask import request
from tacker_agent import TackerAgent
from osm_agent import OSMAgent
from shutil import rmtree
from database import DatabaseConnection
from copy import deepcopy
from cachelib import MemcachedCache


logger = logging.getLogger('core')

database = DatabaseConnection()


class Core:

    def __init__(self):
        # self.database = DatabaseConnection()
        self.cache = MemcachedCache()
        self.tacker_agent = TackerAgent()
        self.osm_agent = OSMAgent()

    def _get_nfvo_agent_instance(self, platform):
        """
        Returns the NFVO Agent instance based on a platform

        :param platform: the NFVO platform from VNF Package
        :return: an instance of NFVO Agent
        """
        # try:
        #     nfvo = getattr(self, platform)
        # except AttributeError:
        #     raise AttributeError('VNF Package\'s %s platform not supported!', platform)

        if platform == TACKER_NFVO:
            return self.tacker_agent
        elif platform == OSM_NFVO:
            return self.osm_agent
        else:
            raise ValueError('VNF Package\'s %s platform not supported!', platform)

    def include_package(self, vnfp_data):
        """
        Includes a VNF Package in the local catalog and in the file repository

        :return: an 'OK' dict status or error and its reason if not
        """
        # TODO: consider also upload the VNF Image to the Tacker and OSM

        vnfd = vnfp_data['vnfd']
        descriptor = json.loads(vnfp_data['descriptor'])

        category = descriptor['category']
        vnf_type = descriptor['type']
        platform = descriptor['platform']
        vnf_description = descriptor['description']

        if vnf_type not in [CLICK_VNF, GENERAL_VNF]:
            return {'status': ERROR, 'reason': 'VNF Package unknown type: %s' % vnf_type}

        dir_id = unique_id()
        dir_name = 'repository/' + dir_id
        os.makedirs(dir_name)

        if platform == TACKER_NFVO:
            vnfd_status, data = TackerAgent.vnfd_json_yaml_parser(vnfd)
            if vnfd_status == OK:
                vnfd = data
            else:
                return {'status': vnfd_status, 'reason': data}

            vnfd_name = vnfd['vnfd']['name']

            vnfd = json.dumps(vnfd, indent=2, sort_keys=True)

            vnfd_file = open(dir_name + '/vnfd.json', 'w')
            vnfd_file.write(vnfd)
            vnfd_file.close()

        elif platform == OSM_NFVO:
            vnfd_bytes = vnfd.encode('utf-8')
            vnfd_base64 = base64.b64decode(vnfd_bytes)

            vnfd_file = open(dir_name + '/vnfd.tar.gz', 'wb')
            vnfd_file.write(vnfd_base64)
            vnfd_file.close()

            # Openning tar file to get the vnfd name
            tar = tarfile.open(dir_name + '/vnfd.tar.gz', 'r:gz')
            tar_files = tar.getnames()
            file_names = [f for f in tar_files if 'vnfd.yaml' in f]
            tar_vnfd = tar.extractfile(tar.getmember(file_names[0]))

            vnfd_yaml = yaml.full_load(tar_vnfd)
            vnfd_name = vnfd_yaml['vnfd:vnfd-catalog']['vnfd'][0]['name']

        else:
            return {'status': ERROR, 'reason': 'VNF Package unknown platform: %s' % platform}

        if vnf_type == CLICK_VNF:
            vnf_code = vnfp_data['vnf']
            vnf_file = open(dir_name + '/vnf.click', 'w')
            vnf_file.write(vnf_code)
            vnf_file.close()

        # TODO: needs to add a function name
        resp, data = database.insert_vnf_package(category, vnfd_name, dir_id, vnf_type, platform, vnf_description)

        if resp == OK:
            return {'status': OK}
        else:
            return {'status': resp, 'reason': data}

    def list_catalog(self):
        """
        List all VNFs in stored in the catalog repository

        :return: a dict of vnfs
        """
        _, vnfs = database.list_catalog()

        return {'vnfs': vnfs}

    def delete_package(self, pkg_id):
        """
        Remove a VNF Package from the local catalog and its repository files

        :param pkg_id: VNF Package identifier
        :return: a dict with status and error reason if it occurs
        """

        _, data = database.list_vnf_instances(vnf_pkg_id=pkg_id)
        if len(data) > 0:
            return {'status': ERROR, 'reason': "A VNF Instance depends on this VNF Package!"}

        resp, catalog = database.list_catalog(pkg_id)
        pkg_dir_id = catalog[0]['dir_id']

        if resp == OK:
            result = database.remove_vnf_package(pkg_id)

            if result == OK:
                try:
                    rmtree('repository/' + pkg_dir_id)
                except OSError as e:
                    logger.error("%s '%s'", e.strerror, e.filename)
                    return {'status': ERROR, 'reason': e.strerror}

                return {'status': OK}

        return {'status': ERROR, 'reason': status[404]}

    def list_vnfs(self):
        """List all instantiated VNFs in NFVO"""

        resp, data = self.tacker_agent.vnf_list()
        if resp != OK:
            return {'status': resp, 'reason': data}

        resp, osm_data = self.osm_agent.vnf_list()
        if resp != OK:
            return {'status': resp, 'reason': data}

        data.extend(osm_data)

        return {'status': OK, 'vnfs': data}

    def instantiate_vnf(self, vnf_pkg_id, issubprocess=False):
        """ Instantiates a given VNF in NFVO

        :param vnf_pkg_id:
        :param issubprocess: states that this function is running in a subprocess
        :return: a dict containing OK, vnfd_id, vnf_id and vnf_ip if success, or ERROR and its reason if not
        """
        db = database

        # it is used to avoid fork racing conditions of the client connection of pymongo
        if issubprocess:
            db = DatabaseConnection()

        resp, catalog = db.list_catalog(vnf_pkg_id=vnf_pkg_id)

        if resp != OK:
            return {'status': ERROR, 'reason': 'VNF Package not found!'}

        dir_id = catalog[0]['dir_id']
        vnfd_name = catalog[0]['vnfd_name']
        vnf_type = catalog[0]['vnf_type']
        platform = catalog[0]['platform']
        vnfp_dir = 'repository/%s' % dir_id

        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except ValueError as e:
            return {'status': ERROR, 'reason': e}

        if vnf_type == CLICK_VNF:
            function_path = 'repository/%s/vnf.click' % dir_id
            with open(function_path) as function_file:
                function_data = function_file.read()

            response = nfvo_agent.vnf_create(vnfp_dir, vnfd_name, unique_id(), function_data)

        else:
            response = nfvo_agent.vnf_create(vnfp_dir, vnfd_name, unique_id())

        if response['status'] != OK:
            return {'status': response['status'], 'reason': response['reason']}

        db_res, data = db.insert_vnf_instance(vnf_pkg_id, response['vnfd_id'], response['vnf_id'])

        # Rollback actions if database inserting fails
        if db_res != OK:
            error_message = 'Database error: %s' % data

            logger.error("Executing rollback actions...\n%s", error_message)

            resp_delete = nfvo_agent.vnf_delete(response['vnf_id'])
            if resp_delete == OK:
                logger.info("Rollback done!")
            else:
                error_message.join([' ', resp_delete['reason']])
                logger.error(error_message)

            return {'status': ERROR, 'reason': error_message}

        # return instantiated vnf data
        return response

    def destroy_vnf(self, vnf_id):
        """Destroys a given VNF in NFVO

        :param vnf_id: the NFVO VNF's ID
        :return: OK if success, or ERROR and its reason if not
        """

        _, vnf_instance = database.list_vnf_instances(vnf_id=vnf_id)
        try:
            _, vnf_pkg = database.list_catalog(vnf_pkg_id=vnf_instance[0]['vnf_pkg_id'])
        except IndexError:
            return {'status': ERROR, 'reason': 'VNF not found in database!'}

        platform = vnf_pkg[0]['platform']

        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except ValueError as e:
            return {'status': ERROR, 'reason': e}

        response = nfvo_agent.vnf_delete(vnf_id)

        if response['status'] != OK:
            return response

        database.remove_vnf_instance(vnf_instance[0]['_id'])

        return {'status': OK}

    def get_vnf_nfvo_resource_id(self, vnf_id, resource_name):
        response = self.tacker_agent.vnf_resources(vnf_id)

        if response['status'] != OK:
            return response

        for resource in response['resources']:
            if resource['name'] == resource_name:
                return {
                    'status': OK,
                    'resource_id': resource['id']
                }

        return {
            'status': ERROR,
            'reason': 'VNF Resource ID not found!'
        }

    def get_vnf_package(self, vnf_id):
        """Retrieves a VNF Package stored in Catalog from a given NFVO's VNF ID

        :param vnf_id:
        :return:
        """

        res, data = database.list_vnf_instances(vnf_id=vnf_id)

        if res == OK:
            if data:
                return {'status': OK, 'package': data[0]}
            else:
                return {'status': ERROR, 'reason': 'VNF Package not found in Catalog!'}

        # if happens a database error
        return {'status': ERROR, 'reason': data}

    def get_policies(self):
        # TODO: check the last ACL criteria in Tacker API
        # TODO: check whether we can get all ACL criteria directly calling the tacker REST API
        acl_criterias = {
            'eth_type': 'Specifies Ethernet frame type (See IEEE 802.3)',
            'eth_src': 'Ethernet source address',
            'eth_dst': 'Ethernet destination address',
            'vlan_id': 'VLAN ID',
            'vlan_pcp': 'VLAN Priority',
            'mpls_label': 'MPLS Label',
            'mpls_tc': 'MPLS Traffic Class',
            'ip_dscp': 'IP DSCP (6 bits in ToS field)',
            'ip_ecn': 'IP ECN (2 bits in ToS field)',
            'ip_src_prefix': 'IP source address prefix',
            'ip_dst_prefix': 'IP destination address prefix',
            'ip_proto': 'IP protocol number',
            'tenant_id': 'OpenStack Tenant ID',
            'icmpv4_type': 'ICMP type',
            'icmpv4_code': 'ICMP code',
            'arp_op': 'ARP opcode',
            'arp_spa': 'ARP source ipv4 address',
            'arp_tpa': 'ARP target ipv4 address',
            'arp_sha': 'ARP source hardware address',
            'arp_tha': 'ARP target hardware address',
            'ipv6_src': 'IPv6 source address',
            'ipv6_dst': 'IPv6 destination address',
            'ipv6_flabel': 'IPv6 Flow Label',
            'icmpv6_type': 'ICMPv6 type',
            'icmpv6_code': 'ICMPv6 code',
            'ipv6_nd_target': 'Target address for ND',
            'ipv6_nd_sll': 'Source link-layer for ND',
            'ipv6_nd_tll': 'Target link-layer for ND',
            'destination_port_range': 'Target port range'
        }
        return {'acl': acl_criterias}

    def create_sfc_uuid(self):
        """Retrieves a unique identifier in order to compose a new SFC

            Retrieves a uuid4 identifier to compose a new SFC and get a copy of the vnffg template.
        :return: a unique identifier str.
        """

        vnffgd = deepcopy(vnffgd_template)
        sfc_uuid = unique_id()

        self.cache.set(sfc_uuid, vnffgd)

        return {'sfc_uuid': sfc_uuid}

    def list_vnf_pkg_cps(self, vnf_pkg_id):
        """Retrieve all connection points of a VNF Package stored in repository

        :param vnf_pkg_id: VNF Package ID
        :return: a dict with all connection points
        """

        _, data = database.list_catalog(vnf_pkg_id)
        dir_id = data[0]['dir_id']

        vnfd_path = 'repository/%s/vnfd.json' % dir_id
        with open(vnfd_path) as vnfd_file:
            vnfd_data = vnfd_file.read()

        vnfd_data = json.loads(vnfd_data)

        node_templates = vnfd_data['vnfd']['attributes']['vnfd']['topology_template']['node_templates']

        cps = {}
        for atr in node_templates.keys():
            if 'tosca.nodes.nfv.CP' in node_templates[atr]['type']:
                virtual_link = node_templates[atr]['requirements'][0]['virtualLink']['node']
                network_name = node_templates[virtual_link]['properties']['network_name']
                cps[atr] = {'virtual_link': virtual_link, 'network_name': network_name}

        return cps

    def compose_sfp(self, sfp_data):
        """Performs VNF Chaining in the VNFFG Template.

        This function stands for VNF Chaining and its requirements for CPs and VLs using the VNFFG Template.
        The first interface is reserved for the VNF management interface, and thus it is not used for VNF chaining.
        The following rules are taken into account:
        - cp_in: chooses the cp_in according to the same network of the prior cp_out. If the VNF is the first one, then
                 the first CP is chosen (disregarding the management interface)
        - cp_out: if the given VNF has just one CP for VNF chaining, then cp_out = cp_in. Otherwise,
                  cp_out is chosen taking into account NFVO requirements implemented in the related agents.
                  If cp_out can not be selected automatically, a message with OPTIONS status is returned
                  in order to the user inform the desirable and suitable connection point.

        :param sfp_data: must be a dict with fields:
            - sfc_uuid: the unique identifier for the SFC being composed
            - vnf_pkg_id: always required
            - cp_out: not required, but can be used as a manually user input

        :return: OK if success, or ERROR and its reason if not, or OPTIONS and a cp_list dict
        """

        try:
            vnffgd = self.cache.get(sfp_data['sfc_uuid'])
            if not vnffgd:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        vnf_pkg_id = sfp_data['vnf_pkg_id']
        vnf_pkg_cps = self.list_vnf_pkg_cps(vnf_pkg_id)
        _, catalog = database.list_catalog(vnf_pkg_id)
        vnfd_name = catalog[0]['vnfd_name']

        # TODO: All the following code is specific to the tacker_agent. Consider move it to there
        topology_template = vnffgd['vnffgd']['template']['vnffgd']['topology_template']

        # verifying if this vnf package was already added to this VNFFG (no duplication allowed)
        if vnfd_name in topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']:
            return {'status': ERROR, 'reason': 'The selected VNF Package was already added on this SFC!'}

        cp_list = sorted(vnf_pkg_cps)
        # we are considering that the Tacker's first CP is always reserved for the VNF management interface
        # Thus, it is not used for VNF chaining
        cp_list.pop(0)

        # gets all virtual links in VNFFGD
        vnffgd_vls = topology_template['groups']['VNFFG1']['properties']['dependent_virtual_link']

        # getting the previous network_name for correct VNF chaining
        previous_net_name = ''
        if vnffgd_vls:
            previous_vl = vnffgd_vls[-1]  # gets the current last VL in VNFFG

            # gets the current last VNF Name in VNFFGD
            previous_vnfd_name = topology_template['groups']['VNFFG1']['properties']['constituent_vnfs'][-1]
            _, previous_vnf_pkg_id = database.list_catalog(vnfd_name=previous_vnfd_name)
            previous_vnf_pkg_id = previous_vnf_pkg_id[0]['_id']

            # gets all connection points data from previous VNFD
            previous_vnfd_cps = self.list_vnf_pkg_cps(previous_vnf_pkg_id)

            for cp in previous_vnfd_cps:
                if previous_vnfd_cps[cp]['virtual_link'] == previous_vl:
                    previous_net_name = previous_vnfd_cps[cp]['network_name']
                    break

        cp_in, cp_out = "", ""
        # including cp_input
        for cp in cp_list:
            if vnffgd_vls:  # if there are previous Virtual Links included in VNFFGD

                # cp_in is valid just if it is connected to the same network_name from previous VNF output
                if vnf_pkg_cps[cp]['network_name'] == previous_net_name:
                    cp_in = cp
                    break

            else:  # if this VNF is the first one being included in VNFFGD
                cp_in = cp
                break

        if not cp_in:
            return {'status': ERROR, 'reason': 'There is no suitable CP to chaining with previous VNF!'}

        # including cp_output
        num_cps = len(cp_list)
        if num_cps == 1:
            cp_out = cp_in
        else:  # num_cps surely will be > 1, because previous return

            # output CP requirements are dependent of NFVO capabilities, thus it was implemented in the related agent
            result, data = self.tacker_agent.select_and_validate_cp_out(sfp_data, vnf_pkg_cps, cp_in)

            if result != OK:
                return data

            cp_out = data

        if cp_in == cp_out:
            capability = [cp_in]
        else:
            capability = [cp_in, cp_out]

        for cp in capability:
            # including connection points
            topology_template['groups']['VNFFG1']['properties']['connection_point'].append(cp)
            # including dependent virtual links
            virtual_link = vnf_pkg_cps[cp]['virtual_link']

            # if virtual_link not in topology_template['groups']['VNFFG1']['properties']['dependent_virtual_link']:
            topology_template['groups']['VNFFG1']['properties']['dependent_virtual_link'].append(virtual_link)

        # including constituent VNFs
        topology_template['groups']['VNFFG1']['properties']['constituent_vnfs'].append(vnfd_name)

        vnf_end_points = len(capability)
        if vnf_end_points == 1:
            capability = capability[0]
        else:
            capability = ','.join(capability)

        # including number of endpoints
        topology_template['groups']['VNFFG1']['properties']['number_of_endpoints'] += vnf_end_points

        path = {"forwarder": vnfd_name, "capability": capability}

        # including VNF forwarding path
        topology_template['node_templates']['Forwarding_path1']['properties']['path'].append(path)

        # debug
        logger.debug('VNFFGD Template UUID: %s\n%s', request.json['sfc_uuid'], json.dumps(vnffgd, indent=4, sort_keys=True))

        self.cache.set(sfp_data['sfc_uuid'], vnffgd)

        return {'status': OK}


    # TODO: consider to move part of this function to tacker_agent if other NFVOs don't need "network_src_port_id" criteria
    def include_classifier_policy(self, policy_data):
        """Includes ACL criteria according to INTERNAL or EXTERNAL traffic source

        INTERNAL traffic is sourced from VNFs managed by NFVO, while EXTERNAL traffic is sourced from everything
        out from NFVO networks.
        This function also includes specific requirements to select the source port for any NFVO.
        Currently, it just supports Tacker NFVO.
        Tacker has the requirement for 'network_source_port_id' in ACL criteria, which is included  in VNFFGD
        by this function.
        One important rule is applied:
            1. Tacker's network_name from the origin VNF CP must be the same as the input CP of the first VNF in the chain.
               If there are more CPs than 1, then a message with status OPTIONS and a cp_list is replied in order to the
               user inform a desirable connection point.

        :param policy_data: input arguments are:
            - sfc_uuid: the unique identifier to the SFC being composed
            - origin: if the SFC traffic source is INTERNAL or EXTERNAL
            - vnf_id: the VNF unique identifier from the NFVO
            - resource: optional when using INTERNAL origin. Identifies the manual user input of the cp_out

        :return: OK if success, or ERROR and its reason if not, or OPTIONS and a cp_list dict
        """

        try:
            vnffgd = self.cache.get(policy_data['sfc_uuid'])
            if not vnffgd:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        # TODO: from here, specific to Tacker. Consider move it to the agent
        origin = policy_data['origin']

        topology_template = vnffgd['vnffgd']['template']['vnffgd']['topology_template']
        # sfp = service function path
        sfp_cps = topology_template['groups']['VNFFG1']['properties']['connection_point']
        sfp_vnfs = topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']
        # network_src_port_id is a requirement for Tacker NFVO
        criteria = topology_template['node_templates']['Forwarding_path1'] \
                                    ['properties']['policy']['criteria']

        _, catalog = database.list_catalog(vnfd_name=sfp_vnfs[0])
        sfp_first_pkg_id = catalog[0]['_id']
        sfp_first_vnf_cps = self.list_vnf_pkg_cps(sfp_first_pkg_id)

        if origin == INTERNAL:
            vnf_id = request.json['vnf_id']

            resp, data = database.list_vnf_instances(vnf_id=vnf_id)
            if resp != OK:
                return {'status': resp, 'reason': data}

            # Only VNFs instantiated by this framework can be used as origin,
            # as we need get information of its CP on VNF Packages
            if not data:
                return {'status': ERROR, 'reason': 'The chosen VNF was not instantiated by Multi-SFC!'}

            vnf_pkg_id = data[0]['vnf_pkg_id']
            vnf_pkg_cps = self.list_vnf_pkg_cps(vnf_pkg_id)

            # Leave just the CPs that are in the same subnet of the first VNF CP_in of the SFC
            cps = vnf_pkg_cps.keys()
            cps = list(cps)
            for cp in cps:
                if vnf_pkg_cps[cp]['network_name'] != sfp_first_vnf_cps[sfp_cps[0]]['network_name']:
                    vnf_pkg_cps.pop(cp)

            # resource means the CP_out
            if 'resource' not in policy_data:
                # Selects the suitable CP_out automatically
                if not vnf_pkg_cps:
                    return {'status': ERROR, 'reason': 'No suitable CP on this VNF!'}

                if len(vnf_pkg_cps) == 1:
                    cp_name = list(vnf_pkg_cps.keys())[0]

                else:
                    return {
                        'status': OPTIONS,
                        'cp_list': vnf_pkg_cps
                    }

            else:
                cp_name = policy_data['resource']

                if cp_name not in vnf_pkg_cps:
                    return {'status': ERROR, 'reason': 'Invalid CP!'}

            response = self.get_vnf_nfvo_resource_id(vnf_id, cp_name)
            if response['status'] != OK:
                return response

            criteria.append({'network_src_port_id': response['resource_id']})

        elif origin == EXTERNAL:
            resp, data = self.tacker_agent.get_fip_router_interface_id(
                                sfp_first_vnf_cps[sfp_cps[0]]['network_name'])

            if resp == OK:
                criteria.append({'network_src_port_id': data})

            else:
                return {
                    'status': resp,
                    'reason': data
                }

        else:
            return {
                'status': ERROR,
                'reason': 'Error 500: Network traffic source to SFP should be INTERNAL or EXTERNAL.'
            }

        # debug
        logger.debug('VNFFGD Template UUID: %s\n%s', request.json['sfc_uuid'], json.dumps(vnffgd, indent=4, sort_keys=True))

        self.cache.set(policy_data['sfc_uuid'], vnffgd)

        return {'status': OK}

    def acl_criteria_parser(self, acl):
        """Parses all ACL criteria according of each NFVO requirements.

        It parses from strings to ints all ACL criteria to match the NFVO requirements.
        Currently just Tacker requirements are implemented.

        :param acl: a dict with the acl criteria
        :return: OK and data if success, or ERROR and its reason if not
        """
        # TODO: this function should be moved to the tacker_agent
        with open('tacker_nfv_defs.yaml', 'r') as defs_file:
            acl_defs = defs_file.read()

        acl_defs = yaml.full_load(acl_defs)
        acl_types = acl_defs['data_types']['tosca.nfv.datatypes.aclType']['properties']

        # TODO: also consider implementing validation constraints: in_range [...] from tacker_nfv_defs.yaml
        for item in acl:
            k = list(item.keys())
            k = k[0]
            if k not in acl_types:
                return ERROR, 'Invalid ACL criteria "%s"!' % k

            if acl_types[k]['type'] == 'integer':
                item[k] = int(item[k])

        return OK, acl

    def configure_policies(self, policy_data):
        """Includes ACL criteria in VNFFGD

        JSON arguments are:
            - sfc_uuid: the unique identifier of the SFC being composed
            - acl: a dict containing the acl criteria to be added into the vnffgd template

        :return: OK if success, or ERROR and its reason if not
        """

        try:
            vnffgd = self.cache.get(policy_data['sfc_uuid'])
            if not vnffgd:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        acl = policy_data['acl']

        # TODO: from here move to tacker_agent
        topology_template = vnffgd['vnffgd']['template']['vnffgd']['topology_template']

        criteria = topology_template['node_templates']['Forwarding_path1'] \
                                    ['properties']['policy']['criteria']

        res, acl = self.acl_criteria_parser(acl)

        if res != OK:
            return {'status': ERROR, 'reason': acl}

        for rule in acl:
            criteria.append(rule)

        #debug
        logger.debug('VNFFGD Template UUID: %s\n%s', request.json['sfc_uuid'], json.dumps(vnffgd, indent=4, sort_keys=True))

        self.cache.set(policy_data['sfc_uuid'], vnffgd)

        return {'status': OK}

    # TODO: Move this function to tacker agent
    def set_next_vnffgd_path_id(self, vnffgd):
        """Set up the next VNFFGD SFP id in the SFC being composed

            Retrieves the largest number of the SFP ID in the vnffgd catalog from the NFVO and sets
            the next one in the currently vnffgd being composed.

        :return: OK and the last path id, or ERROR and its reason
        """
        result, data = self.tacker_agent.vnffgd_list()

        if result != OK:
            return result, data

        last_path_id = 0
        for item in data:
            path_id = item['template']['vnffgd']['topology_template'] \
                          ['node_templates']['Forwarding_path1']['properties']['id']
            if path_id > last_path_id:
                last_path_id = path_id

        vnffgd['vnffgd']['template']['vnffgd']['topology_template'] \
              ['node_templates']['Forwarding_path1']['properties']['id'] = last_path_id + 1

        return OK, last_path_id

    # TODO: Move this function to tacker agent
    def sfc_rollback_actions(self, vnf_instance_ids, vnffgd_id=None):
        """Executes the rollback actions whether an error occurs while instantiating a VNFFG"""

        logger.info("Executing rollback actions...")
        error_message = ''

        if vnffgd_id:
            logger.info("Destroying VNFFGD %s", vnffgd_id)
            resp, data = self.tacker_agent.vnffgd_delete(vnffgd_id)
            if resp != OK:
                return data

        for vnf_id in vnf_instance_ids:
            rollback_data = self.destroy_vnf(vnf_id)
            if rollback_data['status'] != OK:
                error_message = ' '.join([error_message, rollback_data['reason']])
                logger.error(rollback_data['reason'])

        logger.info('Rollback done!')

        return error_message

    def create_sfc(self, sfc_data):
        """Sends and instantiates all VNFDs and VNFFGDs to the NFVO communication agent

        If an error occurs it also calls rollback actions

        :param sfc_data: input parameters are:
            - sfc_uuid: the unique identifier of the composed SFC to be started

        :return: OK if all succeed, or ERROR and its reason
        """

        try:
            vnffgd = self.cache.get(sfc_data['sfc_uuid'])
            if not vnffgd:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        # TODO: from here is specific to tacker agent
        vnf_instance_list = []
        vnf_mapping = {}

        constituent_vnfs = vnffgd['vnffgd']['template']['vnffgd']['topology_template'] \
                                 ['groups']['VNFFG1']['properties']['constituent_vnfs']
        # configuring VNFFGD unique name
        vnffgd['vnffgd']['name'] = unique_id()

        # Instantiating all VNFDs in VNFFGD using processes
        subprocess_pkgs = []
        for vnfd_name in constituent_vnfs:
            result, data = database.list_catalog(vnfd_name=vnfd_name)
            if result != OK:
                return {'status': result, 'reason': data}
            # Second argument states that the called function is in a subprocess
            subprocess_pkgs.append([data[0]['_id'], True])

        processes = Pool(len(subprocess_pkgs))

        proc_resp = processes.starmap(self.instantiate_vnf, subprocess_pkgs)
        processes.close()
        processes.terminate()
        logger.debug('Return data from processes: %s', proc_resp)

        error = False
        for i in range(len(proc_resp)):
            vnf_data = proc_resp[i]
            vnfd_name = constituent_vnfs[i]

            if vnf_data['status'] == OK:
                vnf_instance_list.append(vnf_data['vnf_id'])
                vnf_mapping[vnfd_name] = vnf_data['vnf_id']
            else:
                logger.error("VNF could not be instantiated. Reason: %s", vnf_data['reason'])
                error = True

        # Rollback action if a given VNF fails on instantiating
        if error:
            self.sfc_rollback_actions(vnf_instance_list)
            return {'status': ERROR, 'reason': 'Something went wrong on instantiating VNFs. See server logs.'}
        # Processes to instantiate VNFs until here!!!

        # incrementing SFP path_id number in VNFFGD
        # TODO: consider put the set_next_vnffgd_path_id() in a critical region to avoid condition racing
        result, data = self.set_next_vnffgd_path_id(vnffgd)
        if result != OK:
            message = self.sfc_rollback_actions(vnf_instance_list)
            data = ' '.join([data, message])
            return {'status': result, 'reason': data}

        # create VNFFGD in NFVO
        resp, data = self.tacker_agent.vnffgd_create(vnffgd)
        # TODO: critical region until here

        # show the ultimate created VNFFGD
        logger.info('VNFFGD Template UUID: %s\n%s', request.json['sfc_uuid'], json.dumps(vnffgd, indent=4, sort_keys=True))

        if resp != OK:  # Rollback actions
            message = self.sfc_rollback_actions(vnf_instance_list)
            data = ' '.join([data, message])
            logger.error(data)
            return {'status': resp, 'reason': data}

        vnffgd_id = data
        logger.info("VNFFG descriptor created with id %s", vnffgd_id)

        # instantiate VNFFG
        resp, data = self.tacker_agent.vnffg_create(vnffgd_id, vnf_mapping, unique_id())

        if resp != OK:  # Rollback actions
            message = self.sfc_rollback_actions(vnf_instance_list, vnffgd_id)
            message = ' '.join([data, message])
            return {'status': resp, 'reason': message}

        vnffg_id = data
        logger.info("VNFFG %s instantiated successfully!", vnffg_id)

        resp, data = database.insert_sfc_instance(vnf_instance_list, vnffgd_id, vnffg_id)
        if resp != OK:  # Rollback actions

            vnffg_resp, vnffg_data = self.tacker_agent.vnffg_delete(vnffg_id)
            if vnffg_resp != OK:
                return {'status': vnffg_resp, 'reason': ': '.join(['VNFFG', vnffg_data])}

            message = self.sfc_rollback_actions(vnf_instance_list, vnffgd_id)
            message = ' '.join([data, message])
            return {'status': resp, 'reason': message}

        self.cache.delete(sfc_data['sfc_uuid'])

        return {'status': OK}

    def destroy_sfc(self, sfc_id):
        """Destroy the VNFFG and its VNFs
    
        This function destroys the VNFFG and its VNFFGDs, and also all the VNFs and its VNFDs
        that are specified in the VNFFG
    
        :param sfc_id: the NFVO unique identifier of the VNFFG
        :return: OK if succeed, or ERROR and its reason if not
        """

        # TODO: move all from here to tacker agent
        state, data = self.tacker_agent.vnffg_show(sfc_id)

        if state != OK:
            return {'status': state, 'reason': data}

        vnffgd_id = data['vnffgd_id']
        vnf_mapping = data['vnf_mapping']

        vnffg_vnfs = []
        for vnf_id in vnf_mapping.values():
            vnffg_vnfs.append(vnf_id)

        # destroying VNFFG
        resp, data = self.tacker_agent.vnffg_delete(sfc_id)
        if resp != OK:
            return {'status': resp, 'reason': data}

        # remove SFC_Instance from database
        resp, sfc_instance = database.list_sfc_instances(vnffg_id=sfc_id)
        if resp == OK:
            if len(sfc_instance) > 0:
                _id = sfc_instance[0]['_id']
                database.remove_sfc_instance(_id)

        # TODO: How many time we should wait before remove the VNFFGD?
        time.sleep(2)

        # destroying VNFFGD
        resp, data = self.tacker_agent.vnffgd_delete(vnffgd_id)
        if state != OK:
            return {'status': resp, 'reason': data}

        # destroying VNFs
        message = ''
        for vnf_id in vnffg_vnfs:
            vnf_data = self.destroy_vnf(vnf_id)

            if vnf_data['status'] != OK:
                message = ' '.join([message, '\nVNF id %s: ' % vnf_id, vnf_data['reason']])

        if message:
            return {'status': ERROR, 'reason': message}

        return {'status': OK}

    def list_sfcs(self):
        resp, data = self.tacker_agent.sfc_list()
        if resp != OK:
            return {'status': resp, 'reason': data}

        resp, osm_data = self.osm_agent.sfc_list()
        if resp != OK:
            return {'status': resp, 'reason': data}

        data.extend(osm_data)

        return {'status': OK, 'sfcs': data}
