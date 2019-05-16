#!/usr/bin/env python

import json
import time
from multiprocessing.pool import Pool

import yaml
import logging

from exceptions import NFVOAgentsException, NFVOAgentOptions
from nfvo_agents import NFVOAgents
from interface import implements

from utils import OK, ERROR, ACTIVE, TIMEOUT, TACKER_NFVO, unique_id, status, INTERNAL, EXTERNAL
from tacker import IdentityManager, Tacker
# The package fake_tacker should be used for performance testing or demo purposes. It takes out Tacker NFVO requests
# Also see in the beginning of the "instantiate_vnf" function in "Core" class.
# from fake_tacker import IdentityManager, Tacker


logger = logging.getLogger('tacker_agent')


class TackerAgent(implements(NFVOAgents)):
    """Implementation of the Tacker Agent."""

    def __init__(self):
        self.timeout = 300

        self.identity = IdentityManager()
        token = self.identity.get_token()
        tacker_ep = self.identity.get_endpoints()['tacker']

        self.tacker = Tacker(token, tacker_ep)

    @staticmethod
    def vnfd_json_yaml_parser(vnfd):

        try:
            vnfd = json.loads(vnfd)

        except ValueError:

            try:
                raw_vnfd = yaml.full_load(vnfd)

                try:
                    attr_vnfd = dict()
                    attr_vnfd['tosca_definitions_version'] = raw_vnfd['tosca_definitions_version']
                    attr_vnfd['metadata'] = raw_vnfd['metadata']
                    attr_vnfd['description'] = raw_vnfd['description']
                    attr_vnfd['topology_template'] = raw_vnfd['topology_template']

                    attributes = {'vnfd': attr_vnfd}

                    head = dict()
                    head['description'] = raw_vnfd['description']
                    head['service_types'] = [{'service_type': 'vnfd'}]
                    head['attributes'] = attributes

                    vnfd = dict()
                    vnfd['vnfd'] = head

                except KeyError as e:
                    msg = "YAML error format: %s" % e
                    logger.error(msg)
                    return ERROR, msg

            except yaml.YAMLError:
                msg = "VNFD should be in JSON or YAML format!"
                logger.error(msg)
                return ERROR, msg

        vnfd['vnfd']['name'] = vnfd['vnfd']['attributes']['vnfd']['metadata']['template_name']

        return OK, vnfd

    def vnfd_create(self, vnfd):
        """Create a VNF descriptor and return its ID.

        :param vnfd: VNFD content
        :return:
        """

        response = self.tacker.vnfd_create(vnfd)

        if response.status_code != 201:
            return ERROR, status[response.status_code]

        vnfd_id = response.json()['vnfd']['id']
        return OK, vnfd_id

    def vnfd_delete(self, vnfd_id):
        """Deletes a VNF descriptor and returns the status code

        :param vnfd_id: VNFD ID in the Tacker
        :return: OK if success, or ERROR and its reason if not
        """

        vnfs = self.tacker.vnf_list().json()['vnfs']
        vnfds = []
        for vnf in vnfs:
            vnfds.append(vnf['vnfd_id'])

        if vnfd_id not in vnfds:
            response = self.tacker.vnfd_delete(vnfd_id)

            if response.status_code != 204:
                return ERROR, status[response.status_code]

        return OK, status[204]

    def vnf_vm_create(self, vnfd_id, vnf_name):
        """Create a VNF VM and return its ID."""

        response = self.tacker.vnf_create(vnfd_id, vnf_name)

        if response.status_code != 201:
            return ERROR, status[response.status_code]

        vnf_id = response.json()['vnf']['id']
        return OK, vnf_id

    def polling(self, vnf_id):
        """Constantly checks the creation status of the VNF.

        Wait until the VNF status is set to ACTIVE on Tacker.
        """
        # IMPORTANT: This is not related to Click VNF Functions. Do not confuse it!

        timeout = self.timeout
        sleep_interval = 2

        while timeout > 0:
            response = self.tacker.vnf_show(vnf_id)
            vnf_status = response.json()['vnf']['status']

            if vnf_status == ACTIVE:
                # TODO: what is the better way to retrieve VNF IP? It may change
                #       depending on the VNF descriptor.
                vnf_ip = json.loads(response.json()['vnf']['mgmt_url'])['VDU1']
                return vnf_status, vnf_ip

            elif vnf_status == ERROR:
                error_reason = response.json()['vnf']['error_reason']
                return vnf_status, error_reason

            else:
                time.sleep(sleep_interval)
                timeout -= sleep_interval

        if timeout <= 0:
            error_reason = 'TIMEOUT'
            return TIMEOUT, error_reason

    def vnf_create(self, vnfp_dir, vnfd_name, vnf_name):
        """Create a VNF and initialize all tasks.

        :param vnfp_dir: directory path containing the VNF Package
        :param vnfd_name: a name
        :param vnf_name: a name
        :return: status and some VNF instance data
        """

        vnfd_path = '%s/vnfd.json' % vnfp_dir
        with open(vnfd_path) as vnfd_file:
            vnfd_data = vnfd_file.read()

        vnfd_data = json.loads(vnfd_data)
        vnfd_data['vnfd']['name'] = vnfd_name

        response = self.tacker.vnfd_list()
        if response.status_code != 200:
            return {'status': ERROR, 'reason': status[response.status_code]}

        vnfds = response.json()['vnfds']

        vnfd_id = None
        # Verify if the VNFD name already exists in NFVO
        for vnfd in vnfds:
            if vnfd['name'] == vnfd_data['vnfd']['name']:
                vnfd_id = vnfd['id']
                break

        if not vnfd_id:
            resp, data = self.vnfd_create(json.dumps(vnfd_data))

            if resp == ERROR:
                error_reason = 'VNF descriptor could not be created: %s' % data
                logger.error(error_reason)
                return {'status': resp, 'reason': error_reason}

            vnfd_id = data
            logger.info('VNF descriptor created with id %s', vnfd_id)

        else:
            logger.info('Using an existing VNF descriptor id %s!', vnfd_id)

        # Generating a unique VNF name to avoid Tacker Internal Server Error
        seq = 1
        vnf_name = ''.join([vnf_name, '-', str(seq)])
        _, vnfs = self.vnf_list()
        while True:
            vnf_list = [vnf for vnf in vnfs if vnf['vnf_name'] == vnf_name]
            if len(vnf_list) > 0:
                seq += 1
                vnf_name = vnf_name[:-1] + str(seq)
                continue
            break
        # Unique VNF name until here

        resp, data = self.vnf_vm_create(vnfd_id, vnf_name)

        # Rollback VNFD creation
        if resp == ERROR:
            error_reason = 'VNF could not be created: %s' % data
            logger.error(error_reason)

            remove_status, data = self.vnfd_delete(vnfd_id)
            if remove_status == OK:
                logger.info("VNF descriptor id %s removed.", vnfd_id)
            else:
                logger.error(data)

            return {'status': resp, 'reason': error_reason}

        vnf_id = data
        logger.info('VNF is being created with id %s', vnf_id)

        # Wait until VM is fully created
        resp, data = self.polling(vnf_id)

        if resp in [ERROR, TIMEOUT]:
            error_reason = 'VNF could not be created: %s' % data
            logger.error(error_reason)
            return {'status': resp, 'reason': error_reason}

        vnf_ip = data

        return {
            'status' : OK,
            'vnfd_id': vnfd_id,
            'vnf_id' : vnf_id,
            'vnf_ip' : vnf_ip
        }

    def vnf_delete(self, vnf_id):
        """Deletes a VNF and its VNFD

        :param vnf_id: VNF ID in the Tacker
        :return: OK if success, or ERROR and its reason if not
        """

        vnffgs = self.tacker.vnffg_list().json()['vnffgs']
        vnfs = []
        for vnffg in vnffgs:
            for vnf in vnffg['vnf_mapping'].values():
                vnfs.append(vnf)

        if vnf_id in vnfs:
            message = "A VNFFG depends on this VNF!"
            logger.warning(message)
            return {'status': ERROR, 'reason': message}

        vnfd_id = self.tacker.vnf_show(vnf_id).json()['vnf']['vnfd_id']

        response = self.tacker.vnf_delete(vnf_id)

        if response.status_code != 204:
            error_reason = ''.join(["VNF: ", status[response.status_code]])
            logger.error(error_reason)
            return {'status': ERROR, 'reason': error_reason}

        #  pooling waiting to remove successfully this VNF
        SLEEP_TIME = 2
        while self.timeout > 0:
            time.sleep(SLEEP_TIME)
            vnf = self.tacker.vnf_show(vnf_id)

            if vnf.status_code == 200:
                vnf_status = vnf.json()['vnf']['status']

                if vnf_status == 'ERROR':
                    error_reason = "VNF Status: ERROR"
                    logger.error(error_reason)
                    return {'status': ERROR, 'reason': error_reason}

            elif vnf.status_code == 404:  # it was removed successfully, next: remove its VNFD
                break

            else:
                error_reason = status[vnf.status_code]
                logger.error(error_reason)
                return {'status': ERROR, 'reason': error_reason}

            self.timeout -= SLEEP_TIME

        remove_status, data = self.vnfd_delete(vnfd_id)

        if remove_status == OK:
            return {'status': OK}
        else:
            error_reason = ''.join(["VNFD: ", status[response.status_code]])
            logger.warning(error_reason)
            return {'status': ERROR, 'reason': error_reason}

    def vnf_list(self):
        """ List all Tacker VNFs

        :return: a list of dict containing all Tacker VNFs
        """
        # response = self.tacker.vnf_list().json()['vnfs']
        # logger.debug(json.dumps(response, indent=2))
        response = self.tacker.vnf_list()

        if response.status_code != 200:
            return ERROR, status[response.status_code]

        response = response.json()['vnfs']

        vnfs = []
        for vnf in response:
            vnf_id = vnf['id']
            vnf_name = vnf['name']

            try:
                mgmt_url = json.loads(vnf['mgmt_url'])['VDU1']
            except TypeError:
                mgmt_url = ''

            try:
                instance = vnf['attributes']['heat_template']
                instance = yaml.full_load(instance)
                instance_name = instance['resources']['VDU1']['properties']['name']
            except KeyError:
                instance_name = ''

            vnfd_id = vnf['vnfd_id']
            vnf_status = vnf['status']

            vnfs.append({'vnf_id': vnf_id, 'vnf_name': vnf_name, 'instance_name': instance_name,
                         'mgmt_url': mgmt_url, 'vnfd_id': vnfd_id, 'vnf_status': vnf_status, 'platform': TACKER_NFVO})

        return OK, vnfs

    def vnf_show(self, vnf_id):
        """Get information about a given VNF from Tacker

        :param vnf_id: the ID from a given VNF in Tacker
        :return: a dict with a few information about a given VNF
        """
        response = self.tacker.vnf_show(vnf_id).json()['vnf']

        vnf = {}
        for k, v in iter(response.items()):
            if k in ('id', 'name', 'status', 'vnfd_id', 'error_reason', 'description', 'instance_id'):
                vnf[k] = v
        mgmt_url = json.loads(response['mgmt_url'])['VDU1']
        instance = response['attributes']['heat_template']
        instance = yaml.load(instance)
        instance_name = instance['resources']['VDU1']['properties']['name']

        vnf['mgmt_url'] = mgmt_url
        vnf['instance_name'] = instance_name

        return vnf

    def vnf_nfvo_resources(self, vnf_id):
        """List resources such as VDU and CP."""

        response = self.tacker.vnf_resources(vnf_id)

        if response.status_code != 200:
            raise NFVOAgentsException(ERROR, status[response.status_code])

        resources = response.json()['resources']

        return resources

    def vnffgd_create(self, vnffgd):
        """Create VNF Forwarding Graph Descriptor."""

        response = self.tacker.vnffgd_create(json.dumps(vnffgd))

        if response.status_code != 201:
            return ERROR, status[response.status_code]

        vnffgd_id = response.json()['vnffgd']['id']
        return OK, vnffgd_id

    def vnffgd_list(self):
        """Retrieves the list of VNFFGDs from Tacker"""

        response = self.tacker.vnffgd_list()

        if response.status_code != 200:
            return ERROR, status[response.status_code]

        return OK, response.json()['vnffgds']

    def vnffgd_delete(self, vnffgd_id):
        """Delete a given VNFFGD in Tacker"""

        response = self.tacker.vnffgd_delete(vnffgd_id)

        if response.status_code != 204:
            return ERROR, status[response.status_code]

        logger.info("VNFFGD %s removed successfully!", vnffgd_id)

        return OK, status[response.status_code]

    def vnffg_create(self, vnffgd_id, vnf_mapping, vnffg_name):
        """Create VNF Forwarding Graph."""

        vnf_mapping = json.dumps(vnf_mapping)
        response = self.tacker.vnffg_create(vnffgd_id, vnf_mapping, vnffg_name)

        if response.status_code != 201:
            return ERROR, status[response.status_code]

        vnffg_id = response.json()['vnffg']['id']

        return OK, vnffg_id

    def sfc_list(self):
        """Retrieves the list of VNFFGs in Tacker"""

        response = self.tacker.vnffg_list()

        if response.status_code != 200:
            return ERROR, status[response.status_code]

        sfcs = self.tacker.sfc_list().json()['sfcs']
        # Getting all NFPs' VNF Chain of all SFCs
        nfps = {}
        for sfc in sfcs:
            vnf_chain = []
            for vnf in sfc['chain']:
                vnf_chain.append(vnf['name'])

            nfps[sfc['nfp_id']] = vnf_chain

        vnffgs = []
        for vnffg in response.json()['vnffgs']:
            vnffg_id = vnffg['id']
            name = vnffg['name']
            state = vnffg['status']
            desc = vnffg['description']
            vnffgs.append({
                'id': vnffg_id,
                'name': name,
                'status': state,
                'description': desc,
                'vnf_chain': nfps[vnffg['forwarding_paths']],
                'platform': TACKER_NFVO
            })

        return OK, vnffgs

    def vnffg_show(self, vnffg_id):
        """Retrieves a given VNFFG in Tacker"""

        response = self.tacker.vnffg_show(vnffg_id)

        if response.status_code != 200:
            return ERROR, status[response.status_code]

        return OK, response.json()['vnffg']

    def vnffg_delete(self, vnffg_id):
        """Deletes a given VNFFG in Tacker"""

        response = self.tacker.vnffg_delete(vnffg_id)

        if response.status_code != 204:
            return ERROR, status[response.status_code]

        logger.info("VNFFG %s destroyed successfully!", vnffg_id)

        return OK, status[response.status_code]

    def get_fip_router_interface_id(self, net_name):
        """Retrieves Floating IP router network port ID

        :param net_name: Network name to retrieve the router port ID (gateway)
        :return: OK and network_src_port_id, or ERROR and its reason
        """
        net_interfaces = self.identity.get_fip_router_interfaces()
        if net_name not in net_interfaces:
            msg = "Router Floating IP interface not configured for '%s' network in tacker.conf" % net_name
            logger.error(msg)
            raise NFVOAgentsException(ERROR, msg)

        return net_interfaces[net_name]

    def select_and_validate_cp_out(self, options_cp_out, vnf_pkg_cps, cp_in):
        """Selects and validates the CP_out based on Tacker NFVO requirements

            Verify if there is another CP attached to subnet of cp_in. If not, return all CPs with OPTIONS reply.
            If there are more than 1 CP attached to subnet of cp_in, return OPTIONS status and the suitable CPs
            in order to the user select one of them as output CP.
            It also verifies if cp_out has a value. If yes, validate if it is attached to the same net of cp_in.
            OBS: Tacker/Pike does not work yet on SFCs using different subnets.
            Therefore, each SFC must be composed in the same subnet.

        :param options_cp_out: the output connection point
        :param vnf_pkg_cps: a dict containing the vnf package connection points and its subnet names
        :param cp_in: cp_in connection point name
        :return: OK and CP_out if validated, or OPTIONS, reason and cp_list if it was not possible to select
                 CP_out automatically
        """
        cp_out = options_cp_out
        # Leave just the CPs that are in the same subnet as CP_in (Tacker/Pike requirement)
        cps = vnf_pkg_cps.keys()
        cps = list(cps)
        for cp in cps:
            if vnf_pkg_cps[cp]['network_name'] != vnf_pkg_cps[cp_in]['network_name']:
                vnf_pkg_cps.pop(cp)

        # We are assuming that there are more than 1 CP using a same subnet. So, SFC_Core could not
        # select cp_out automatically, and user must inform a CP_out.
        if not options_cp_out:
            # Case all other CPs are from other subnets, then there is only 1 CP available
            if len(vnf_pkg_cps) == 1:
                cp_out = cp_in

            else:
                # Tacker/Pike does not work with Input and Output CPs belonging to the same subnet
                # return OPTIONS, {
                #     'status': OPTIONS,
                #     'reason': 'Inform the outgoing traffic CP',
                #     'cp_list': vnf_pkg_cps
                # }
                cp_out = cp_in

        else:
            # vnf_pkg_cps will has here only the CPs which have the same subnet of CP_in
            if options_cp_out not in vnf_pkg_cps:
                raise NFVOAgentOptions('Invalid CP!', vnf_pkg_cps)

        return cp_out

    def get_policies(self):
        """Returns the Tacker classifier ACL"""

        return {
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

    def get_sfc_template(self):
        return {
            "vnffgd": {
                "name": "vnffgd1",
                "template": {
                    "vnffgd": {
                        "tosca_definitions_version": "tosca_simple_profile_for_nfv_1_0_0",
                        "description": "Sample VNFFG template",
                        "topology_template": {
                            "node_templates": {
                                "Forwarding_path1": {
                                    "type": "tosca.nodes.nfv.FP.Tacker",
                                    "description": "creates path (CP12->CP22)",
                                    "properties": {
                                        "policy": {
                                            "type": "ACL",
                                            "criteria": []
                                        },
                                        "path": [],
                                        "id": 0
                                    }
                                }
                            },
                            "description": "Sample VNFFG template",
                            "groups": {
                                "VNFFG1": {
                                    "type": "tosca.groups.nfv.VNFFG",
                                    "description": "HTTP to Corporate Net",
                                    "members": [
                                        "Forwarding_path1"
                                    ],
                                    "properties": {
                                        "vendor": "tacker",
                                        "connection_point": [],
                                        "version": 1.0,
                                        "constituent_vnfs": [],
                                        "number_of_endpoints": 0,
                                        "dependent_virtual_link": []
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    def list_vnf_pkg_cps(self, vnfp_dir):
        """Retrieve all connection points of a VNF Package stored in repository

        :param vnfp_dir: VNF Package directory name (from repository)
        :return: a dict with all connection points
        """

        vnfd_path = 'repository/%s/vnfd.json' % vnfp_dir
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

    def compose_sfp(self, sfc_descriptor, vnfd_name, vnfp_dir, database, options_cp_out):

        vnf_pkg_cps = self.list_vnf_pkg_cps(vnfp_dir)

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']

        # verifying if this vnf package was already added to this VNFFG (no duplication allowed)
        if vnfd_name in topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']:
            raise NFVOAgentsException(ERROR, 'The selected VNF Package was already added in this SFC!')

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
            _, previous_vnf_pkg = database.list_catalog(vnfd_name=previous_vnfd_name)
            previous_vnfp_dir = previous_vnf_pkg[0]['dir_id']

            # gets all connection points data from previous VNFD
            previous_vnfd_cps = self.list_vnf_pkg_cps(previous_vnfp_dir)

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
            raise NFVOAgentsException(ERROR, 'There is no suitable CP to chaining with the previous VNF!')

        # including cp_output
        num_cps = len(cp_list)
        if num_cps == 1:
            cp_out = cp_in
        else:  # num_cps surely will be > 1, because previous return

            # output CP requirements are dependent of NFVO capabilities, thus it was implemented in the related agent
            cp_out = self.select_and_validate_cp_out(options_cp_out, vnf_pkg_cps, cp_in)

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

        return sfc_descriptor

    def get_vnf_nfvo_resource_id(self, vnf_id, resource_name):
        resources = self.vnf_nfvo_resources(vnf_id)

        for resource in resources:
            if resource['name'] == resource_name:
                return resource['id']

        raise NFVOAgentsException(ERROR, 'VNF Resource ID not found!')

    def configure_traffic_src_policy(self, sfc_descriptor, origin, vnf_id, cp_out, database):

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']
        # sfp = service function path
        sfp_cps = topology_template['groups']['VNFFG1']['properties']['connection_point']
        sfp_vnfs = topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']
        # network_src_port_id is a requirement for Tacker NFVO
        criteria = topology_template['node_templates']['Forwarding_path1'] \
            ['properties']['policy']['criteria']

        _, catalog = database.list_catalog(vnfd_name=sfp_vnfs[0])
        sfp_first_pkg_dir_id = catalog[0]['dir_id']
        sfp_first_vnf_cps = self.list_vnf_pkg_cps(sfp_first_pkg_dir_id)

        if origin == INTERNAL:
            # vnf_id = request.json['vnf_id']

            resp, data = database.list_vnf_instances(vnf_id=vnf_id)
            if resp != OK:
                raise NFVOAgentsException(resp, data)

            # Only VNFs instantiated by this framework can be used as origin,
            # as we need get information of its CP on VNF Packages
            if not data:
                raise NFVOAgentsException(ERROR, 'The chosen VNF was not instantiated by Multi-SFC!')

            vnf_pkg_id = data[0]['vnf_pkg_id']
            _, catalog = database.list_catalog(vnf_pkg_id=vnf_pkg_id)
            vnf_pkg_dir = catalog[0]['dir_id']
            vnf_pkg_cps = self.list_vnf_pkg_cps(vnf_pkg_dir)

            # Leave just the CPs that are in the same subnet of the first VNF CP_in of the SFC
            cps = vnf_pkg_cps.keys()
            cps = list(cps)
            for cp in cps:
                if vnf_pkg_cps[cp]['network_name'] != sfp_first_vnf_cps[sfp_cps[0]]['network_name']:
                    vnf_pkg_cps.pop(cp)

            if cp_out is None:
                # Selects the suitable CP_out automatically
                if not vnf_pkg_cps:
                    raise NFVOAgentsException(ERROR, 'No suitable CP on this VNF!')

                if len(vnf_pkg_cps) == 1:
                    cp_name = list(vnf_pkg_cps.keys())[0]

                else:
                    raise NFVOAgentOptions('Choose an CP!', vnf_pkg_cps)

            else:
                cp_name = cp_out

                if cp_name not in vnf_pkg_cps:
                    raise NFVOAgentsException(ERROR, 'Invalid CP!')

            resource_id = self.get_vnf_nfvo_resource_id(vnf_id, cp_name)

            criteria.append({'network_src_port_id': resource_id})

        elif origin == EXTERNAL:
            data = self.tacker_agent.get_fip_router_interface_id(
                sfp_first_vnf_cps[sfp_cps[0]]['network_name'])

            criteria.append({'network_src_port_id': data})

        else:
            raise NFVOAgentsException(ERROR, 'Network traffic source to SFP should be INTERNAL or EXTERNAL.')

        return sfc_descriptor

    def acl_criteria_parser(self, acl):
        """Parses all ACL criteria according of Tacker NFVO requirements.

        It parses from strings to ints all ACL criteria to match the NFVO requirements.

        :param acl: a dict with the acl criteria
        :return: OK and data if success, or ERROR and its reason if not
        """

        with open('tacker_nfv_defs.yaml', 'r') as defs_file:
            acl_defs = defs_file.read()

        acl_defs = yaml.full_load(acl_defs)
        acl_types = acl_defs['data_types']['tosca.nfv.datatypes.aclType']['properties']

        for item in acl:
            k = list(item.keys())
            k = k[0]
            if k not in acl_types:
                msg = 'Invalid ACL criteria "%s"!' % k
                logger.info(msg)
                raise NFVOAgentsException(ERROR, msg)

            if 'constraints' in acl_types[k]:
                item_range = acl_types[k]['constraints'][0]['in_range']
                start, end = item_range
                if int(item[k]) not in range(start, end+1):
                    msg = "Invalid value for ACL criteria '%s'! Use a value between %s and %s." % (k, start, end)
                    logger.info(msg)
                    raise NFVOAgentsException(ERROR, msg)

            if acl_types[k]['type'] == 'integer':
                item[k] = int(item[k])

        return acl

    def configure_policies(self, sfc_descriptor, acl):

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']

        criteria = topology_template['node_templates']['Forwarding_path1'] \
            ['properties']['policy']['criteria']

        acl = self.acl_criteria_parser(acl)

        for rule in acl:
            criteria.append(rule)

        return sfc_descriptor

    def set_next_vnffgd_path_id(self, vnffgd):
        """Set up the next VNFFGD SFP id in the SFC being composed

            Retrieves the largest number of the SFP ID in the vnffgd catalog from the NFVO and sets
            the next one in the currently vnffgd being composed.

        :return: OK and the last path id, or ERROR and its reason
        """
        result, data = self.vnffgd_list()

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

    def sfc_rollback_actions(self, vnf_instance_ids, core, vnffgd_id=None):
        """Executes the rollback actions whether an error occurs while instantiating a VNFFG"""

        logger.info("Executing rollback actions...")
        error_message = ''

        if vnffgd_id:
            logger.info("Destroying VNFFGD %s", vnffgd_id)
            resp, data = self.vnffgd_delete(vnffgd_id)
            if resp != OK:
                return data

        for vnf_id in vnf_instance_ids:
            rollback_data = core.destroy_vnf(vnf_id)
            if rollback_data['status'] != OK:
                error_message = ' '.join([error_message, rollback_data['reason']])
                logger.error(rollback_data['reason'])

        logger.info('Rollback done!')

        return error_message

    def create_sfc(self, sfc_descriptor, database, core, sfc_uuid):
        """Sends and instantiates all VNFDs and VNFFGDs to the NFVO communication agent

        If an error occurs it also calls rollback actions

        :param sfc_data: input parameters are:
            - sfc_uuid: the unique identifier of the composed SFC to be started

        :return: OK if all succeed, or ERROR and its reason
        """
        # TODO Corrigir os argumentos na documentação de todo o código
        vnf_instance_list = []
        vnf_mapping = {}

        constituent_vnfs = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template'] \
            ['groups']['VNFFG1']['properties']['constituent_vnfs']
        # configuring VNFFGD unique name
        sfc_descriptor['vnffgd']['name'] = unique_id()

        # Instantiating all VNFDs in VNFFGD using processes
        subprocess_pkgs = []
        for vnfd_name in constituent_vnfs:
            result, data = database.list_catalog(vnfd_name=vnfd_name)
            if result != OK:
                return {'status': result, 'reason': data}
            # Second argument states that the called function is in a subprocess
            subprocess_pkgs.append([data[0]['_id'], True])

        processes = Pool(len(subprocess_pkgs))

        proc_resp = processes.starmap(core.instantiate_vnf, subprocess_pkgs)
        processes.close()
        processes.terminate()
        # debug
        logger.info('Return data from processes: %s', proc_resp)

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
            self.sfc_rollback_actions(vnf_instance_list, core)
            return {'status': ERROR, 'reason': 'Something went wrong on instantiating VNFs. See server logs.'}
        # Processes to instantiate VNFs up to here!!!

        # incrementing SFP path_id number in VNFFGD
        # Consider put the set_next_vnffgd_path_id() in a CRITICAL REGION to avoid condition racing
        result, data = self.set_next_vnffgd_path_id(sfc_descriptor)
        if result != OK:
            message = self.sfc_rollback_actions(vnf_instance_list, core)
            data = ' '.join([data, message])
            return {'status': result, 'reason': data}

        # create VNFFGD in NFVO
        resp, data = self.vnffgd_create(sfc_descriptor)
        # Critical Region up to here

        # show the ultimate created VNFFGD
        logger.info('SFC Template UUID: %s\n%s', sfc_uuid,
                    json.dumps(sfc_descriptor, indent=4, sort_keys=True))

        if resp != OK:  # Rollback actions
            message = self.sfc_rollback_actions(vnf_instance_list, core)
            data = ' '.join([data, message])
            logger.error(data)
            return {'status': resp, 'reason': data}

        vnffgd_id = data
        logger.info("SFC descriptor created with id %s", vnffgd_id)

        # instantiate VNFFG
        resp, data = self.vnffg_create(vnffgd_id, vnf_mapping, unique_id())

        if resp != OK:  # Rollback actions
            message = self.sfc_rollback_actions(vnf_instance_list, core, vnffgd_id)
            message = ' '.join([data, message])
            return {'status': resp, 'reason': message}

        vnffg_id = data
        logger.info("SFC %s instantiated successfully!", vnffg_id)

        resp, data = database.insert_sfc_instance(vnf_instance_list, vnffgd_id, vnffg_id)
        if resp != OK:  # Rollback actions

            vnffg_resp, vnffg_data = self.vnffg_delete(vnffg_id)
            if vnffg_resp != OK:
                return {'status': vnffg_resp, 'reason': ': '.join(['VNFFG', vnffg_data])}

            message = self.sfc_rollback_actions(vnf_instance_list, core, vnffgd_id)
            message = ' '.join([data, message])
            return {'status': resp, 'reason': message}

        return {'status': OK}

    def destroy_sfc(self, sfc_id, core):
        """Destroy the VNFFG and its VNFs

        This function destroys the VNFFG and its VNFFGDs, and also all the VNFs and its VNFDs
        that are specified in the VNFFG

        :param sfc_id: the NFVO unique identifier of the VNFFG
        :raises: NFVOAgentsException
        """

        state, data = self.vnffg_show(sfc_id)

        if state != OK:
            raise NFVOAgentsException(state, data)

        vnffgd_id = data['vnffgd_id']
        vnf_mapping = data['vnf_mapping']

        vnffg_vnfs = []
        for vnf_id in vnf_mapping.values():
            vnffg_vnfs.append(vnf_id)

        # destroying VNFFG
        vnffg_status, data = self.vnffg_delete(sfc_id)
        if vnffg_status != OK:
            raise NFVOAgentsException(vnffg_status, data)

        # TODO: How many time should we wait before remove the VNFFGD?
        time.sleep(2)

        # destroying VNFFGD
        vnffgd_status, data = self.vnffgd_delete(vnffgd_id)
        if state != OK:
            raise NFVOAgentsException(vnffgd_status, data)

        # destroying VNFs
        message = ''
        for vnf_id in vnffg_vnfs:
            vnf_data = core.destroy_vnf(vnf_id)

            if vnf_data['status'] != OK:
                message = ' '.join([message, '\nVNF id %s: ' % vnf_id, vnf_data['reason']])

        if message:
            raise NFVOAgentsException(ERROR, message)
