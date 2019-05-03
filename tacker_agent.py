#!/usr/bin/env python

import json
import time
import yaml
import logging

from nfvo_agents import NFVOAgents
from interface import implements

from click_manager import ElementManagement
from utils import *
from tacker import *
# The package fake_tacker should be used for performance testing or demo purposes. It takes out Tacker NFVO requests
# Also see beginning of the "vnf_create" function. To do it, tacker package must be replaced by fake_tacker
# from fake_tacker import *


logger = logging.getLogger('tacker_agent')


class TackerAgent(implements(NFVOAgents)):
    """Implementation of the Tacker Agent."""

    def __init__(self):
        self.timeout = 300
        self.em = ElementManagement()

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

        vnfd['vnfd']['name'] = unique_id()

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
        sleep_interval = 0.5

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

    def click_init(self, vnf_id, vnf_ip, function):
        """Once Click VNF VM is running, initialize all tasks.

        Wait at least 10 seconds until Click VNF is ready to initialize its tasks
        The waiting timeout is up to 30 seconds before trying to write and start the function
        Each test is executed on port TCP 8000 using intervals of 2 seconds, in order to not break the Click HTTP Server
        """

        logger.info('VNF %s Initializing click dependencies' % vnf_id)

        # Wait until all vnf-level dependencies are fully loaded
        # TODO: What is the best way to determine this sleep time? It may change from one system to another.
        # Use 10 seconds when click takes much time to initialize, because the Click-on-OSv HTTP Server
        # breaks if a connection is done before the all dependencies are fully loaded.
        time.sleep(10)
        # time.sleep(5)

        timeout = time.time() + 30
        sleep_interval = 2

        while timeout > time.time():
            try:

                resp = self.em.is_ready(vnf_ip, vnf_id)
                if resp:
                    break
                time.sleep(sleep_interval)

            except Exception as e:
                logger.error('Something went wrong in click_init function: %s' % e)

        try:
            # send function to VNF VM
            response = self.em.write_function(vnf_ip, function)
            # TODO: It returns status_core=200 even that the function has been started or not
            # Maybe look at the response "text" parameter
            if response.status_code != 200:
                message = 'Unable to write click function. %s' % response.text
                logger.error(message)
                return {'status': ERROR, 'reason': message}

            # start VNF function
            response = self.em.start_function(vnf_ip)
            # TODO: It returns status_core=200 even that the function has been started or not
            # Maybe look at the response "text" parameter
            if response.status_code != 200:
                message = 'Unable to start click function. %s' % response.text
                logger.error(message)
                return {'status': ERROR, 'reason': message}

        except Exception as e:
            message = 'VNF %s functions not initialized: %s' % (vnf_id, e)
            logger.error(message)
            return {
                'status': ERROR,
                'reason': message
            }

        return {'status': OK}

    def vnf_create(self, vnfd_data, vnf_name, click_function=None):
        """Create a VNF and initialize all tasks.

        :param vnfd_data: VNFD content
        :param vnf_name: a name
        :param click_function: if this is a Click VNF, then this param must have the click function content
        :return: status and a few VNF instance data
        """
        # PERFORMANCE TEST and DEMO mode: uncomment the line below in order to use fake_tacker.py
        # click_function = None

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
        logger.info('VNF %s is active with IP %s', vnf_id, vnf_ip)

        if click_function:
            resp = self.click_init(vnf_id, vnf_ip, click_function)
            if resp['status'] != OK:
                return resp

            logger.info('VNF %s functions initialized', vnf_id)

        logger.info('VNF %s successfully created', vnf_id)

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
        logger.info('Destroying VNF Instance %s', vnf_id)

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

    def vnf_resources(self, vnf_id):
        """List resources such as VDU and CP."""

        response = self.tacker.vnf_resources(vnf_id)

        if response.status_code != 200:
            return {
                'status': ERROR,
                'reason': status[response.status_code]
            }

        resources = response.json()['resources']
        return {
            'status': OK,
            'resources': resources
        }

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
                         'mgmt_url': mgmt_url, 'vnfd_id': vnfd_id, 'vnf_status': vnf_status})

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

    def sfc_create(self, vnffgd, vnf_mapping):
        """Create a Service Function Chaining."""

        # create vnffgd
        status, data = self.vnffgd_create(vnffgd)

        if status == ERROR:
            error_reason = 'VNFFGD could not be created: %s' % data
            logger.error(error_reason)
            return {'status': status, 'reason': error_reason}

        vnffgd_id = data
        logger.info('VNFFGD created with id %s', vnffgd_id)

        # create VNF Forwarding Graph
        status, data = self.vnffg_create(vnffgd_id, vnf_mapping, unique_id())

        if status == ERROR:
            error_reason = 'VNF Forwarding Graph could not be created: %s' % data
            logger.error(error_reason)
            return {'status': status, 'reason': error_reason}

        vnffg_id = data
        logger.info('VNFFG created with id %s', vnffg_id)

        logger.info('VNFFG %s successfully created', vnffg_id)

        return {
            'status': OK,
            'vnffgd_id': vnffgd_id,
            'vnffg_id': vnffg_id
        }

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

    def vnffg_list(self):
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
                'vnf_chain': nfps[vnffg['forwarding_paths']]
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
            return ERROR, msg

        return OK, net_interfaces[net_name]

    def select_and_validate_cp_out(self, request_data, vnf_pkg_cps, cp_in):
        """Selects and validates the CP_out based on Tacker NFVO requirements

            Verify if there is another CP attached to subnet of cp_in. If not, return all CPs with OPTIONS reply.
            If there are more than 1 CP attached to subnet of cp_in, return OPTIONS status and the suitable CPs
            in order to the user select one of them as output CP.
            It also verifies if cp_out has a value. If yes, validate if it is attached to the same net of cp_in.
            OBS: Tacker/Pike does not work yet on SFCs using different subnets.
            Therefore, each SFC must be composed in the same subnet.

        :param request_data: a dict containing the request data
        :param vnf_pkg_cps: a dict containing the vnf package connection points and its subnet names
        :param cp_in: cp_in connection point name
        :return: OK and CP_out if validated, or OPTIONS, reason and cp_list if it was not possible to select
                 CP_out automatically
        """
        # cp_out = ''
        # Leave just the CPs that are in the same subnet as CP_in (Tacker/Pike requirement)
        cps = vnf_pkg_cps.keys()
        cps = list(cps)
        for cp in cps:
            if vnf_pkg_cps[cp]['network_name'] != vnf_pkg_cps[cp_in]['network_name']:
                vnf_pkg_cps.pop(cp)

        # We are assuming that there are more than 1 CP using a same subnet. So, SFC_Core could not
        # select cp_out automatically, and user must inform a CP_out.
        if 'cp_out' not in request_data.keys():
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
            cp_out = request_data['cp_out']
            # vnf_pkg_cps will has here only the CPs which have the same subnet of CP_in
            if cp_out not in vnf_pkg_cps:
                return OPTIONS, {
                    'status': OPTIONS,
                    'reason': 'Invalid CP!',
                    'cp_list': vnf_pkg_cps
                }

        return OK, cp_out
