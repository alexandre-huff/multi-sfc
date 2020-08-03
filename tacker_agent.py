#!/usr/bin/env python

import json
import time
import yaml
import logging

from queue import Queue
from threading import Thread

from multiprocessing.pool import Pool
from exceptions import NFVOAgentsException, NFVOAgentOptions, VIMAgentsException
from nfvo_agents import NFVOAgents
from interface import implements

from openstack_agent import OpenStackAgent
from utils import OK, ERROR, ACTIVE, TIMEOUT, TACKER_NFVO, INTERNAL, EXTERNAL
from tacker import Tacker
# The package fake_tacker should be used for performance testing or demo purposes. It takes out Tacker NFVO requests
# Also see in the beginning of the "create_vnf" function in "Core" class.
# from fake_tacker import IdentityManager, Tacker


REACHABLE = "REACHABLE"

logger = logging.getLogger('tacker_agent')


class TackerAgent(implements(NFVOAgents)):
    """Implementation of the Tacker Agent."""

    def __init__(self, auth_url, username, password, tenant_name, vim_name, vim_username, vim_password,
                 domain_id, domain_name, nfvo_id, nfvo_name):
        self.vim_name = vim_name
        self._vim_username = vim_username
        self._vim_password = vim_password

        self.nfvo_name = nfvo_name
        self.domain_name = domain_name
        self.domain_id = domain_id
        self.nfvo_id = nfvo_id

        self.tacker = Tacker(auth_url, username, password, tenant_name)

        self.vim_id = self._get_vim_id()

    def _get_vim_id(self):
        vims = self.tacker.vim_list()

        for vim in vims:
            if vim['name'] == self.vim_name:
                return vim['id']

        msg = "VIM '%s' not found in '%s' platform!" % (self.vim_name, self.nfvo_name)
        logger.critical(msg)
        exit(1)

    def get_vim_agent_instance(self):
        """Instantiates a VIM Agent

        Raises
        ------
            NFVOAgentsException
        """
        vim_data = self.tacker.vim_show(self.vim_id)
        if vim_data['type'] != 'openstack':
            msg = "VIM type %s not supported." % vim_data['type']
            logger.error(msg)
            raise NFVOAgentsException(ERROR, msg)

        vim_agent = OpenStackAgent(vim_data['auth_url'],
                                   self._vim_username,
                                   self._vim_password,
                                   vim_data['vim_project']['name'],
                                   self.vim_name
                                   )
        return vim_agent

    @staticmethod
    def vnfd_json_yaml_parser(vnfd):
        """Parses and returns a vnfd

        Raises
        ------
            NFVOAgentsException
        """

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
                    raise NFVOAgentsException(ERROR, msg)

            except yaml.YAMLError:
                msg = "VNFD should be in JSON or YAML format!"
                logger.error(msg)
                raise NFVOAgentsException(ERROR, msg)

        vnfd['vnfd']['name'] = vnfd['vnfd']['attributes']['vnfd']['metadata']['template_name']

        return vnfd

    def create_vnfd(self, vnfd):
        """Create a VNF descriptor and return its ID.

        :param vnfd: VNFD content
        :return: vnfd_id

        Raises
        ------
            NFVOAgentsException
        """

        try:
            response = self.tacker.vnfd_create(vnfd)

        except NFVOAgentsException as e:
            error_reason = 'VNF descriptor could not be created: %s' % e.reason
            logger.error(error_reason)
            raise NFVOAgentsException(ERROR, error_reason)

        return response['id']

    def delete_vnfd(self, vnfd_id):
        """Deletes a VNF descriptor in NFVO

        :param vnfd_id: VNFD ID in the Tacker

        ReRaises
        ------
            NFVOAgentsException
        """

        vnfs = self.tacker.vnf_list()
        vnfds = []
        for vnf in vnfs:
            vnfds.append(vnf['vnfd_id'])

        if vnfd_id not in vnfds:
            try:
                self.tacker.vnfd_delete(vnfd_id)

            except NFVOAgentsException as e:
                error_msg = 'Unable to delete VNFD id %s: %s' % (vnfd_id, e.reason)
                logger.error(error_msg)
                raise NFVOAgentsException(ERROR, error_msg)

    def create_vnf_vm(self, vnfd_id, vnf_name):
        """Create a VNF VM and return its ID.

        Raises
        ------
            NFVOAgentsException
        """
        vim = self.tacker.vim_show(self.vim_id)

        if not vim:
            raise NFVOAgentsException(ERROR, "VIM name '%s' not found in '%s'!" % (self.vim_name, self.nfvo_name))

        vim_status = vim['status']

        # TODO remove the checking of PENDING status below
        """
        PENDING was added here as a work-around since mistral-lib version 2.2.0 from pip on kolla-ansible
        installation does not change the status of the Vim to REACHABLE
        """
        if vim_status not in (REACHABLE, 'PENDING'):
            raise NFVOAgentsException(ERROR, "VIM status of '%s' is '%s' in '%s' platform!"
                                      % (self.vim_name, vim_status, self.nfvo_name))

        try:
            vnf = self.tacker.vnf_create(vnfd_id, vnf_name, self.vim_id)

        except NFVOAgentsException as e:
            error_reason = 'VNF could not be created. status_code: %d, reason: %s' % (e.status, e.reason)
            logger.error(error_reason)
            raise NFVOAgentsException(ERROR, error_reason)

        return vnf['id']

    def polling(self, vnf_id):
        """Constantly checks the creation status of the VNF.

        Wait until the VNF status is set to ACTIVE on Tacker.

        :return: VNF IP address

        Raises
        ------
            NFVOAgentsException
        """
        # IMPORTANT: This is not related to Click VNF Functions. Do not confuse it!

        timeout = 300
        sleep_interval = 2

        while timeout > 0:
            vnf = self.tacker.vnf_show(vnf_id)
            vnf_status = vnf['status']

            if vnf_status == ACTIVE:
                vnf_ip = json.loads(vnf['mgmt_ip_address'])['VDU1']
                return vnf_ip

            elif vnf_status == ERROR:
                error_reason = vnf['error_reason']
                raise NFVOAgentsException(ERROR, error_reason)

            else:
                time.sleep(sleep_interval)
                timeout -= sleep_interval

        if timeout <= 0:
            error_reason = 'TIMEOUT'
            raise NFVOAgentsException(TIMEOUT, error_reason)

    def create_vnf(self, vnfp_dir, vnfd_name, vnf_name):
        """Create a VNF and initialize all tasks.

        :param vnfp_dir: directory path containing the VNF Package
        :param vnfd_name: a name
        :param vnf_name: a name
        :return: some VNF instance data

        Raises
        ------
            NFVOAgentsException
        """

        vnfd_path = '%s/vnfd.json' % vnfp_dir
        with open(vnfd_path) as vnfd_file:
            vnfd_data = vnfd_file.read()

        vnfd_data = json.loads(vnfd_data)
        vnfd_data['vnfd']['name'] = vnfd_name

        vnfds = self.tacker.vnfd_list()

        vnfd_id = None
        # Verify if the VNFD name already exists in NFVO
        for vnfd in vnfds:
            if vnfd['name'] == vnfd_data['vnfd']['name']:
                vnfd_id = vnfd['id']
                break

        if not vnfd_id:
            vnfd_id = self.create_vnfd(json.dumps(vnfd_data))
            logger.info('VNF descriptor created with id %s', vnfd_id)

        else:
            logger.info('Using an existing VNF descriptor id %s!', vnfd_id)

        # Generating a unique VNF name to avoid Tacker Internal Server Error
        vnfs = self.tacker.vnf_list()
        seq = 1
        vnf_name = ''.join([vnf_name, '-', str(seq)])
        while True:
            vnf_list = [vnf for vnf in vnfs if vnf['name'] == vnf_name]
            if len(vnf_list) > 0:
                seq += 1
                vnf_name = vnf_name[:-1] + str(seq)
                continue
            break
        # Unique VNF name up to here

        try:
            vnf_id = self.create_vnf_vm(vnfd_id, vnf_name)

        # Rollback VNFD creation
        except NFVOAgentsException as e:
            try:
                self.delete_vnfd(vnfd_id)
                logger.info("VNF descriptor id %s removed.", vnfd_id)

            # in case of error on deleting VNFD
            except NFVOAgentsException as ex:
                logger.error(ex.reason)
                e.reason = ' '.join([e.reason, ex.reason])

            raise NFVOAgentsException(e.status, e.reason)

        logger.info('VNF is being created with id %s', vnf_id)

        # Wait until VM is fully created
        try:
            vnf_ip = self.polling(vnf_id)

        # in case of polling exception
        except NFVOAgentsException as e:
            error_reason = 'VNF could not be created: %s' % e.reason
            logger.error(error_reason)
            raise NFVOAgentsException(e.status, error_reason)

        return {
            'vnfd_id': vnfd_id,
            'vnf_id': vnf_id,
            'vnf_ip': vnf_ip
        }

    def destroy_vnf(self, vnf_id):
        """Destroys a VNF and deletes its VNFD

        :param vnf_id: VNF ID in the Tacker

        Raises
        ------
            NFVOAgentsException
        """

        vnffgs = self.tacker.vnffg_list()
        vnfs = []
        for vnffg in vnffgs:
            for vnf in vnffg['vnf_mapping'].values():
                vnfs.append(vnf)

        if vnf_id in vnfs:
            message = "A VNFFG depends on this VNF!"
            logger.warning(message)
            raise NFVOAgentsException(ERROR, message)

        vnfd_id = self.tacker.vnf_show(vnf_id)['vnfd_id']

        try:
            self.tacker.vnf_delete(vnf_id)

        except NFVOAgentsException as e:
            error_reason = 'Unable to remove VNF. status_code: %d, reason: %s' % (e.status, e.reason)
            logger.error(error_reason)
            raise NFVOAgentsException(ERROR, error_reason)

        #  polling waiting to remove successfully this VNF
        timeout = 300
        sleep_interval = 2
        while timeout > 0:
            timeout -= sleep_interval
            time.sleep(sleep_interval)
            try:
                vnf = self.tacker.vnf_show(vnf_id)

            except NFVOAgentsException as e:
                if e.status == 404:  # error 404 means not found, i.e. VNF has been deleted
                    break
                else:
                    error_reason = 'Unable to get VNF %s. %s' % (vnfd_id, e.reason)
                    logger.error(error_reason)
                    raise NFVOAgentsException(ERROR, error_reason)

            if vnf and vnf['status'] != 'PENDING_DELETE':
                error_reason = "VNF in %s status!" % vnf['status']
                logger.error(error_reason)
                raise NFVOAgentsException(ERROR, error_reason)

        self.delete_vnfd(vnfd_id)

    def list_vnfs(self):
        """ List all Tacker VNFs

        :return: a list of dict containing all Tacker VNFs

        Raises
        ------
            NFVOAgentsException
        """
        response = self.tacker.vnf_list()

        vnfs = []
        for vnf in response:
            vnf_id = vnf['id']
            vnf_name = vnf['name']

            try:
                mgmt_url = json.loads(vnf['mgmt_ip_address'])['VDU1']
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

            if vnf['vim_id'] == self.vim_id:
                vnfs.append({
                    'vnf_id': vnf_id,
                    'vnf_name': vnf_name,
                    'instance_name': instance_name,
                    'mgmt_url': mgmt_url,
                    'vnfd_id': vnfd_id,
                    'vnf_status': vnf_status,
                    'platform': TACKER_NFVO,
                    'domain_name': self.domain_name,
                    'nfvo_name': self.nfvo_name,
                    'vim_name': self.vim_name
                })

        return vnfs

    def show_vnf(self, vnf_id):
        """Get information about a given VNF from Tacker

        :param vnf_id: the ID from a given VNF in Tacker
        :return: a dict with a few information about a given VNF

        Raises
        ------
            NFVOAgentsException
        """
        vnf = {}
        response = self.tacker.vnf_show(vnf_id)

        if response:
            # for k, v in iter(response.items()):
            #     if k in ('id', 'name', 'status', 'vnfd_id', 'error_reason', 'description', 'instance_id'):
            #         vnf[k] = v
            mgmt_url = json.loads(response['mgmt_ip_address'])['VDU1']
            instance = response['attributes']['heat_template']
            instance = yaml.full_load(instance)
            instance_name = instance['resources']['VDU1']['properties']['name']

            vnf['id'] = response['id']
            vnf['name'] = response['name']
            vnf['status'] = response['status']
            vnf['error_reason'] = response['error_reason']
            vnf['vnfd_id'] = response['vnfd_id']
            vnf['mgmt_address'] = mgmt_url
            vnf['vm_name'] = instance_name

        return vnf

    def list_vnf_nfvo_resources(self, vnf_id):
        """List resources such as VDU and CP.

        ReRaises
        ------
            NFVOAgentsException
        """

        resources = self.tacker.vnf_resources(vnf_id)

        return resources

    def create_vnffgd(self, vnffgd):
        """Create VNF Forwarding Graph Descriptor in Tacker.

        :return: Tacker's VNFFGD ID

        Raises
        ------
            NFVOAgentsException
        """

        try:
            response = self.tacker.vnffgd_create(vnffgd)

        except NFVOAgentsException as e:
            error_reason = 'VNFFG descriptor could not be created: %s' % e.reason
            logger.error(error_reason)
            raise NFVOAgentsException(ERROR, error_reason)

        return response['id']

    def list_vnffgds(self):
        """Retrieves the list of VNFFGDs from Tacker

        ReRaises
        ------
            NFVOAgentsException
        """

        vnffgds = self.tacker.vnffgd_list()

        return vnffgds

    def delete_vnffgd(self, vnffgd_id):
        """Delete a given VNFFGD in Tacker

        Raises
        ------
            NFVOAgentsException
        """

        try:
            self.tacker.vnffgd_delete(vnffgd_id)

        except NFVOAgentsException as e:
            error_msg = 'Unable to delete VNFFGD id %s: %s' % (vnffgd_id, e.reason)
            logger.error(error_msg)
            raise NFVOAgentsException(ERROR, error_msg)

        logger.info("VNFFGD %s removed successfully!", vnffgd_id)

    def create_vnffg(self, vnffgd_id, vnf_mapping, vnffg_name):
        """Create VNF Forwarding Graph.

        :return: Tacker's VNFFG ID

        Raises
        ------
            NFVOAgentsException
        """

        vnf_mapping = json.dumps(vnf_mapping)

        try:
            vnffg = self.tacker.vnffg_create(vnffgd_id, vnf_mapping, vnffg_name)

        except NFVOAgentsException as e:
            error_msg = 'Unable to instantiate VNFFG name %s: %s' % (vnffg_name, e.reason)
            logger.error(error_msg)
            raise NFVOAgentsException(ERROR, error_msg)

        return vnffg['id']

    def show_vnffg(self, vnffg_id):
        """Retrieves a given VNFFG in Tacker

        Raises
        ------
            NFVOAgentsException
        """

        vnffg = self.tacker.vnffg_show(vnffg_id)

        return vnffg

    def vnffg_list(self):
        """Retrieves all VNFFGs from Tacker

        ReRaises
        ------
            NFVOAgentsException
        """

        vnffgs = self.tacker.vnffg_list()

        return vnffgs

    def destroy_vnffg(self, vnffg_id):
        """Deletes a given VNFFG in Tacker

        Raises
        ------
            NFVOAgentsException
        """

        try:
            self.tacker.vnffg_delete(vnffg_id)

        except NFVOAgentsException as e:
            error_msg = 'Unable to destroy VNFFG id %s: %s' % (vnffg_id, e.reason)
            logger.error(error_msg)
            raise NFVOAgentsException(ERROR, error_msg)

        logger.info("VNFFG %s destroyed successfully!", vnffg_id)

    def list_sfcs(self):
        """Retrieves the list of SFCs in Tacker

        :return: a list of VNFFGs with particular fields

        Raises
        ------
            NFVOAgentsException
        """

        response = self.tacker.vnffg_list()
        sfcs = self.tacker.sfc_list()

        # Getting the VNF Chain of each NFP from all SFCs
        nfps = {}
        for sfc in sfcs:
            vnf_chain = []
            for vnf in sfc['chain']:
                vnf_chain.append(vnf['name'])

            nfps[sfc['nfp_id']] = vnf_chain

        vnffgs = []
        for vnffg in response:
            vnffg_id = vnffg['id']
            name = vnffg['name']
            state = vnffg['status']
            # desc = vnffg['description']
            criteria = vnffg['attributes']['vnffgd']['topology_template']['node_templates']['Forwarding_path1'] \
                            ['properties']['policy']['criteria']
            policies = []
            for classifier in criteria:
                data = classifier['classifier']
                data.pop('network_src_port_id')
                policies.append(data)

            vnffgs.append({
                'id': vnffg_id,
                'name': name,
                'status': state,
                'policy': policies,
                'vnf_chain': nfps[vnffg['forwarding_paths']],
                'platform': TACKER_NFVO
            })

        return vnffgs

    def get_fip_router_interface_id(self, net_name):
        """Retrieves Floating IP router network port ID

        :param net_name: Network name to retrieve the router port ID (gateway)
        :return: network_src_port_id

        Raises
        ------
            NFVOAgentsException
        """
        vim_agent = self.get_vim_agent_instance()

        try:
            src_port_id = vim_agent.get_fip_router_interface(net_name)
        except VIMAgentsException as e:
            msg = "Router Floating IP interface not configured for network '%s'. %s" % (net_name, e.reason)
            logger.error(msg)
            raise NFVOAgentsException(ERROR, msg)

        return src_port_id

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
        :return: CP_out if validated

        Raises
        ------
            :NFVOAgentOptions: if it was not possible to select CP_out automatically
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

    def get_available_policies(self):
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
                                    "type": "tosca.nodes.nfv.FP.TackerV2",
                                    "description": "creates path (CP12->CP22)",
                                    "properties": {
                                        "policy": {
                                            "type": "ACL",
                                            "criteria": [
                                                {
                                                    "name": "classifier1",
                                                    "classifier": {}
                                                }
                                            ]
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

    def get_policies(self, sfc_descriptor):
        """Retrieves the configured policies in the sfc descriptor

        :return: a list containing key:value elements
        """

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']
        criteria = topology_template['node_templates']['Forwarding_path1']['properties']['policy']['criteria']
        policies = []
        for classifier in criteria:
            policies.append(classifier['classifier'])

        return policies

    def get_sfc_input_security_policy_data(self, sfc_descriptor):
        """Retrieves security policy data required to configure security policies

        :param sfc_descriptor:
        :return: a list of dicts containing the IP protocol number, port_range_min, port_range_max
                [{proto: 6, min_port: 80 , max_port: 80}]
        """
        policies = self.get_policies(sfc_descriptor)

        policy_data = []
        for policy in policies:
            data = {}
            if 'ip_proto' in policy:
                data['proto'] = policy['ip_proto']
            if 'destination_port_range' in policy:
                dst_range = policy['destination_port_range']
                dst_range = dst_range.split(sep='-')
                data['min_port'] = dst_range[0]
                data['max_port'] = dst_range[1]
            policy_data.append(data)

        return policy_data

    def list_vnf_pkg_cps(self, vnfp_dir):
        """Retrieve all connection points of a VNF Package stored in repository

        :param vnfp_dir: VNF Package directory name
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
        """Performs VNF Chaining in the VNFFG Template.

        This function stands for VNF Chaining and its requirements for CPs and VLs using the VNFFG Template.
        The first interface is reserved for the VNF management interface, and thus it is not used for VNF chaining.
        The following rules are taken into account:

        :cp_in: chooses the cp_in according to the same network of the prior cp_out.
                If the VNF is the first one, then the first CP is chosen (disregarding the management interface)
        :cp_out: if the given VNF has just one CP for VNF chaining, then cp_out = cp_in.
                  If cp_out can not be selected automatically, a exception with OPTIONS status is raised
                  in order to the user inform the desirable and suitable connection point.

        :param sfc_descriptor: the VNFFG descriptor being composed
        :param vnfd_name:
        :param vnfp_dir:
        :param database:
        :param options_cp_out: not required, but it can be used for manual choosing of cp_out
        :return: the Tacker SFC Descriptor (i.e. VNFFGD) being composed

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            NFVOAgentOptions, DatabaseException
        """

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
            previous_vnf_pkg = database.list_catalog(vnfd_name=previous_vnfd_name)
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
            raise NFVOAgentsException(ERROR, 'There is no suitable CP for chaining with the previous VNF!')

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

        # TODO we disabled sfc_encap since our VNFs are NSH-unaware (i.e. VNFs are receiving MPLS packets from OVS)
        # As a result we are only creating SFCs using NSH-unaware VNFs. NSH-aware VNFs still need to be implemented
        path = {"forwarder": vnfd_name,
                "capability": capability,
                "sfc_encap": False}  # hard coded

        # including VNF forwarding path
        topology_template['node_templates']['Forwarding_path1']['properties']['path'].append(path)

        return sfc_descriptor

    def get_vnf_nfvo_resource_id(self, vnf_id, resource_name):
        """Retrieves the NFVO resource ID (such as VDU and CP) from from a particular VNF

        :param vnf_id:
        :param resource_name: the resource name to get the ID

        Raises
        ------
            NFVOAgentsException
        """
        resources = self.list_vnf_nfvo_resources(vnf_id)

        for resource in resources:
            if resource['name'] == resource_name:
                return resource['id']

        raise NFVOAgentsException(ERROR, 'VNF Resource ID not found!')

    def get_sfc_traffic_origin(self, core):
        # fields defines which information should be shown dynamically by client applications
        fields = [
            {'id': 'ID'},
            {'name': 'Name'},
            {'instance': 'Instance Name'},
            {'address': 'Mgmt Address'},
            {'status': 'Status'},
            {'platform': 'Platform'}
        ]

        vnfs = self.list_vnfs()

        src_vnfs = []
        for vnf in vnfs:
                src_vnf = {
                    'id': vnf.get('vnf_id'),
                    'name': vnf.get('vnf_name'),
                    'instance': vnf.get('instance_name'),
                    'address': vnf.get('mgmt_url'),
                    'status': vnf.get('vnf_status'),
                    'platform': TACKER_NFVO
                }
                src_vnfs.append(src_vnf)

        return fields, src_vnfs

    def configure_traffic_src_policy(self, sfc_descriptor, origin, src_id, cp_out, database):
        """
        Includes ACL criteria according to INTERNAL or EXTERNAL traffic source

        INTERNAL traffic is sourced from VNFs managed by NFVO, while EXTERNAL traffic is sourced from everything
        out from NFVO networks.
        This function also includes specific requirements to select the source port for Tacker.
        Tacker has the requirement for 'network_source_port_id' in ACL criteria, which is included  in VNFFGD
        by this function.
        One important rule is applied:
            1. Tacker's network_name from the origin VNF CP must be the same as the input CP of the first VNF in the chain.
               If there are more CPs than 1, then a message with status OPTIONS and a cp_list is replied to the
               user to inform a desirable connection point.

        :param sfc_descriptor:
        :param origin: INTERNAL or EXTERNAL as in *utils module*
        :param src_id: the Tacker's VNF ID of the VNF which generates the SFC incoming traffic
        :param cp_out:
        :param database:
        :return: the VNFFGD being composed

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            DatabaseException
        """
        net_src_port_id = None

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']
        # sfp = service function path
        sfp_cps = topology_template['groups']['VNFFG1']['properties']['connection_point']
        sfp_vnfs = topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']
        # network_src_port_id is a requirement for Tacker NFVO
        criteria = topology_template['node_templates']['Forwarding_path1']['properties']['policy']['criteria']

        catalog = database.list_catalog(vnfd_name=sfp_vnfs[0])
        sfp_first_pkg_dir_id = catalog[0]['dir_id']
        sfp_first_vnf_cps = self.list_vnf_pkg_cps(sfp_first_pkg_dir_id)

        if origin == INTERNAL:

            data = database.list_vnf_instances(vnf_id=src_id)
            # Only VNFs instantiated by this framework can be used as origin,
            # as we need get information of its CP on VNF Packages
            if not data:
                raise NFVOAgentsException(ERROR, 'The chose VNF was not instantiated by this framework!')

            vnf_pkg_id = data[0]['vnf_pkg_id']
            catalog = database.list_catalog(vnf_pkg_id=vnf_pkg_id)
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

            net_src_port_id = self.get_vnf_nfvo_resource_id(src_id, cp_name)

        elif origin == EXTERNAL:
            net_src_port_id = self.get_fip_router_interface_id(sfp_first_vnf_cps[sfp_cps[0]]['network_name'])

        else:
            raise NFVOAgentsException(ERROR, 'SFC network traffic should be INTERNAL or EXTERNAL.')

        if not net_src_port_id:
            logger.error('Unable to get a value for network_src_port_id')
            raise NFVOAgentsException(ERROR, 'Unable to get the source port id to configure the SFC classifier')

        # currently multi-sfc uses only one network_src_port_id for all classifiers (the same)
        # the configure_policies gets this value and uses for all subsequent classifiers
        for classifier in criteria:
            classifier['classifier']['network_src_port_id'] = net_src_port_id

        return sfc_descriptor

    def acl_criteria_parser(self, acl):
        """Parses all ACL criteria according of Tacker NFVO requirements.

        It parses from strings to ints all ACL criteria to match the NFVO requirements.

        :param acl: a dict with the acl criteria
        :return: a dict with the parsed acl criteria

        Raises
        ------
            NFVOAgentsException
        """

        with open('tacker_nfv_defs.yaml', 'r') as defs_file:
            acl_defs = defs_file.read()

        acl_defs = yaml.full_load(acl_defs)
        acl_types = acl_defs['data_types']['tosca.nfv.datatypes.aclType']['properties']

        tmp_acl = acl.copy()
        for k, v in tmp_acl.items():
            if k not in acl_types:
                msg = 'Invalid ACL criteria "%s"!' % k
                logger.error(msg)
                raise NFVOAgentsException(ERROR, msg)

            if 'constraints' in acl_types[k]:
                item_range = acl_types[k]['constraints'][0]['in_range']
                start, end = item_range
                if int(v) not in range(start, end+1):
                    msg = "Invalid value for ACL criteria '%s'! Use a value between %s and %s." % (k, start, end)
                    logger.error(msg)
                    raise NFVOAgentsException(ERROR, msg)

            if acl_types[k]['type'] == 'integer':
                acl[k] = int(v)

        return acl

    def configure_policies(self, sfc_descriptor, policies):
        """Configure ACL rules for all Tacker SFC classifiers"""

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']

        criteria = topology_template['node_templates']['Forwarding_path1']['properties']['policy']['criteria']

        net_src_port_id = criteria[0]['classifier'].get('network_src_port_id')

        criteria.clear()  # remove the partial data of the first classifier to build all of them in one shot (simplify)

        for acl in policies:  # acl is the content of a policy
            acl = self.acl_criteria_parser(acl)
            acl['network_src_port_id'] = net_src_port_id
            classifier = {
                "classifier": acl
                # classifier unique name is configured in create_sfc function, since the SFC name is required
                # "name": ""
            }
            criteria.append(classifier)

        return sfc_descriptor

    def set_next_vnffgd_path_id(self, vnffgd):
        """Set up the next VNFFGD SFP id in the SFC being composed

            Retrieves the largest number of the SFP ID in the vnffgd catalog from the NFVO and sets
            the next one in the currently vnffgd being composed.

        :return: the vnffgd begin composed

        ReRaises
        ------
            NFVOAgentsException
        """
        data = self.list_vnffgds()

        last_path_id = 0
        for item in data:
            path_id = item['template']['vnffgd']['topology_template'][
                'node_templates']['Forwarding_path1']['properties']['id']
            if path_id > last_path_id:
                last_path_id = path_id

        vnffgd['vnffgd']['template']['vnffgd']['topology_template'][
            'node_templates']['Forwarding_path1']['properties']['id'] = last_path_id + 1

        return vnffgd

    def destroy_sfc_actions(self, destroy_vnf_fn, vnf_instance_ids=None, vnffgd_id=None, vnffg_id=None):
        """Executes the required actions do destroy an SFC

        This function can be employed on a regular workflow to destroy SFCs, and on rollback actions due to
        errors while creating an SFC

        :param destroy_vnf_fn: callback function from the core module
        :param vnf_instance_ids: a list of vnf instance ids to destroy, only required if vnffg_id is None
        :param vnffgd_id: the vnffg descriptor id to remove, only required if vnffg_id is None
        :param vnffg_id: the vnffg id to remove, if any

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            NFVOAgentsException
        """
        vnffg_vnfs = []  # list of vnf ids to destroy

        if vnffg_id:
            data = self.show_vnffg(vnffg_id)

            vnffgd_id = data['vnffgd_id']
            vnf_mapping = data['vnf_mapping']

            for vnf_id in vnf_mapping.values():
                vnffg_vnfs.append(vnf_id)

            # destroying VNFFG
            self.destroy_vnffg(vnffg_id)

            # How many time should we wait before remove the VNFFGD?
            time.sleep(2)

        # destroying VNFFGD
        if vnffgd_id:  # we need to check since rollback action might not have passed this argument
            self.delete_vnffgd(vnffgd_id)

        if vnf_instance_ids and not vnffg_vnfs:  # we only use value of vnf_instance_ids on rollback actions
            vnffg_vnfs = vnf_instance_ids

        # destroying all VNFs and VNFDs using threads, I/O bound, no GLI problem
        workers = []
        queue = Queue()  # queue to get return values from threads
        for vnf_id in vnffg_vnfs:
            t = Thread(target=destroy_vnf_fn, args=(vnf_id, queue))
            t.start()
            workers.append(t)

        for w in workers:  # waiting all threads to finish
            w.join()

        logger.debug('Returned data from threads: %s', list(queue.queue))

        message = ''
        while not queue.empty():
            vnf_data = queue.get()

            if vnf_data['status'] != OK:
                message = ''.join([message, vnf_data['reason'], ' '])

            queue.task_done()
        # Threads to destroy VNFs up to here!!!

        if message:
            raise NFVOAgentsException(ERROR, message)

    def create_sfc(self, sfc_descriptor, database, sfc_uuid, sfc_name, create_vnf_fn, destroy_vnf_fn):
        """Sends and instantiates all VNFDs and VNFFGDs to the Tacker NFVO

        If an error occurs it also calls rollback actions

        :param sfc_descriptor: the VNFFGD to be instantiated
        :param database:
        :param sfc_uuid: the unique identifier of the composed SFC to be started
        :param sfc_name: the name of the SFC being instantiated (optional)
        :param create_vnf_fn: callback function from the core module
        :param destroy_vnf_fn: callback function from the core module

        :return: a dict containing:

            - a list of *vnf_instances* of the created SFC
            - the created *vnffgd_id*
            - the created *vnffg_id*

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            NFVOAgentsException, DatabaseException
        """
        vnffgd_list = self.list_vnffgds()
        vnffg_list = self.vnffg_list()
        vnffgds = [x for x in vnffgd_list if x['name'] == sfc_name]
        vnffgs = [x for x in vnffg_list if x['name'] == sfc_name]

        if vnffgds or vnffgs:
            raise NFVOAgentsException(ERROR, "SFC name '%s' already exists" % sfc_name)

        vnf_instance_list = []
        vnf_mapping = {}

        topology_template = sfc_descriptor['vnffgd']['template']['vnffgd']['topology_template']
        constituent_vnfs = topology_template['groups']['VNFFG1']['properties']['constituent_vnfs']

        # configuring VNFFGD unique name
        sfc_descriptor['vnffgd']['name'] = sfc_name

        # configuring classifiers human readable unique names
        criteria = topology_template['node_templates']['Forwarding_path1']['properties']['policy']['criteria']
        for index, classifier in enumerate(criteria, start=1):
            classifier['name'] = sfc_name + '-classifier{}'.format(index)

        # Instantiating all VNFDs in VNFFGD using threads, I/O bound, no GLI problem
        workers = []
        queue = Queue()  # queue to get return values from thread
        pkgs = []  # packages to be instantiated
        for vnfd_name in constituent_vnfs:
            data = database.list_catalog(vnfd_name=vnfd_name)

            vnfp_data = {
                'vnfp_id': data[0]['_id'],
                'domain_id': self.domain_id,
                'nfvo_id': self.nfvo_id
            }
            pkgs.append(vnfp_data)

        for pkg in pkgs:
            t = Thread(target=create_vnf_fn, args=(pkg, queue))
            t.start()
            workers.append(t)

        for w in workers:  # waiting all threads to finish
            w.join()

        logger.debug('Returned data from threads: %s', list(queue.queue))

        error = False
        while not queue.empty():
            vnf_data = queue.get()

            if vnf_data['status'] == OK:
                # vnf_instance_list.append(vnf_data['vnf_id'])
                vnfd_name = vnf_data['vnfd_name']
                vnf_mapping[vnfd_name] = vnf_data['vnf_id']
            else:
                logger.error("VNF could not be instantiated. Reason: %s", vnf_data['reason'])
                error = True

            queue.task_done()
        # Threads to instantiate VNFs up to here!!!

        # VNF instance list needs to be ordered according to the VNFFGD to avoid errors on instantiating tunnels
        # This is required because this version of Tacker agent instantiates VNFFGs using threads instead of
        # using a single call to create a NS from a NSD
        for vnfd_name in constituent_vnfs:
            vnf_instance_list.append(vnf_mapping[vnfd_name])

        # Rollback action if a given VNF fails on instantiating
        if error:
            logger.info("Executing rollback actions...")
            self.destroy_sfc_actions(destroy_vnf_fn, vnf_instance_list)
            logger.info('Rollback done!')
            raise NFVOAgentsException(ERROR, 'Something went wrong on instantiating VNFs. See server logs.')

        vnffgd_id = None
        try:
            # incrementing SFP path_id number in VNFFGD
            # Consider put the set_next_vnffgd_path_id() in a CRITICAL REGION to avoid condition racing
            sfc_descriptor = self.set_next_vnffgd_path_id(sfc_descriptor)

            # show the ultimate created VNFFGD
            logger.info('SFC Template UUID: %s\n%s', sfc_uuid,
                        self.dump_sfc_descriptor(sfc_descriptor))

            # create VNFFGD in NFVO
            vnffgd_id = self.create_vnffgd(sfc_descriptor)
            # Critical Region up to here

            logger.info("SFC descriptor created with id %s", vnffgd_id)

            # instantiate VNFFG
            vnffg_id = self.create_vnffg(vnffgd_id, vnf_mapping, sfc_name)

        # Rollback actions
        except NFVOAgentsException as e:
            logger.error('Unable to instantiate SFC: %s', e.reason)
            try:
                logger.info("Executing rollback actions...")
                self.destroy_sfc_actions(destroy_vnf_fn, vnf_instance_list, vnffgd_id)
                logger.info('Rollback done!')

            except NFVOAgentsException as ex:
                logger.error('Unable to execute rollback actions: %s', ex.reason)
                message = ' '.join([e.reason, 'Rollback:', ex.reason])
                raise NFVOAgentsException(ERROR, message)

            raise

        return {
            'vnf_instances': vnf_instance_list,
            'nsd_id': vnffgd_id,
            'ns_id': vnffg_id
        }

    def destroy_sfc(self, sfc_id, destroy_vnf_fn):
        """Destroy the VNFFG and its VNFs

        This function destroys the VNFFG and its VNFFGDs, and also all the VNFs and its VNFDs
        that are specified in the VNFFG

        :param sfc_id: the NFVO unique identifier of the VNFFG
        :param destroy_vnf_fn: callback function from the core module

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            NFVOAgentsException
        """

        try:
            self.destroy_sfc_actions(destroy_vnf_fn, vnffg_id=sfc_id)

        except NFVOAgentsException as e:
            logger.error('Unable to destroy SFC %s, reason: %s', sfc_id, e.reason)
            raise

    def dump_sfc_descriptor(self, sfc_descriptor):
        return json.dumps(sfc_descriptor, indent=2, sort_keys=True)
