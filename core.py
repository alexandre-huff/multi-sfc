#!/usr/bin/env python

import logging
import json
import yaml
import os
import time
import base64
import tarfile

from click_manager import ElementManagement
from exceptions import NFVOAgentsException, NFVOAgentOptions, MultiSFCException
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
        self.click_em = ElementManagement()

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
            msg = "VNF Package '%s' platform not supported!" % platform
            logger.info(msg)
            raise MultiSFCException(msg)

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

            nsd = vnfp_data['nsd']
            nsd_bytes = nsd.encode('utf-8')
            nsd_base64 = base64.b64decode(nsd_bytes)
            nsd_file = open(dir_name + '/nsd.tar.gz', 'wb')
            nsd_file.write(nsd_base64)
            nsd_file.close()

            # Opening VNFD tar file to get the vnfd name
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
        """ Instantiates a given VNF and initialize its function in NFVO

        :param vnf_pkg_id:
        :param issubprocess: states that this function is running in a subprocess
        :return: a dict containing OK, vnfd_id, vnf_id and vnf_ip if success, or ERROR and its reason if not
        """
        # PERFORMANCE TEST and DEMO mode: uncomment the line below in order to use fake_tacker.py
        # click_function = None

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

        vnf_name = str(vnfd_name).replace('vnfd', 'vnf')

        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        response = nfvo_agent.vnf_create(vnfp_dir, vnfd_name, vnf_name)

        if response['status'] != OK:
            return {'status': response['status'], 'reason': response['reason']}

        logger.info('VNF %s is active with IP %s', response['vnf_id'], response['vnf_ip'])

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

        if vnf_type == CLICK_VNF:
            function_path = 'repository/%s/vnf.click' % dir_id
            with open(function_path) as function_file:
                function_data = function_file.read()

            resp = self.click_init(response['vnf_id'], response['vnf_ip'], function_data)
            if resp['status'] != OK:
                return resp

            logger.info('VNF %s function initialized', response['vnf_id'])

        logger.info('VNF %s instantiated successfully', response['vnf_id'])

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
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        logger.info('Destroying VNF Instance %s', vnf_id)

        response = nfvo_agent.vnf_delete(vnf_id)

        if response['status'] != OK:
            return response

        logger.info('VNF Instance %s destroyed successfully', vnf_id)

        database.remove_vnf_instance(vnf_instance[0]['_id'])

        return {'status': OK}

    def click_init(self, vnf_id, vnf_ip, click_function):
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

        # timeout = time.time() + 30
        # sleep_interval = 2
        # while timeout > time.time():
        #     try:
        #
        #         resp = self.click_em.is_ready(vnf_ip, vnf_id)
        #         if resp:
        #             break
        #         time.sleep(sleep_interval)
        #
        #     except Exception as e:
        #         logger.error('Something went wrong in click_init function: %s' % e)

        try:
            # send function to VNF VM
            response = self.click_em.write_function(vnf_ip, click_function)
            # TODO: It returns status_core=200 even that the function has been started or not
            # Maybe look at the response "text" parameter
            if response.status_code != 200:
                message = 'Unable to write click function. %s' % response.text
                logger.error(message)
                return {'status': ERROR, 'reason': message}

            # start VNF function
            response = self.click_em.start_function(vnf_ip)
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

    def get_policies(self, platform):
        """Retrieves the NFVO classifier ACL"""
        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        acl_criterias = nfvo_agent.get_policies()

        return {'acl': acl_criterias}

    def create_sfc_uuid(self):
        """Retrieves a unique identifier in order to compose a new SFC

            Retrieves a uuid4 identifier to compose a new SFC and get a copy of the vnffg template.
        :return: a unique identifier str.
        """

        sfc_uuid = unique_id()
        self.cache.set(sfc_uuid, {})

        return {'sfc_uuid': sfc_uuid}

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
            sfc_template = self.cache.get(sfp_data['sfc_uuid'])
            if sfc_template is None:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        cp_out = sfp_data.get('cp_out')

        vnf_pkg_id = sfp_data['vnf_pkg_id']
        _, catalog = database.list_catalog(vnf_pkg_id)
        vnfd_name = catalog[0]['vnfd_name']
        vnf_pkg_dir = catalog[0]['dir_id']
        platform = catalog[0]['platform']

        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        if platform not in sfc_template:
            sfc_template[platform] = deepcopy(nfvo_agent.get_sfc_template())

        try:
            sfc_template[platform] = nfvo_agent.compose_sfp(sfc_template[platform], vnfd_name, vnf_pkg_dir,
                                                            database, cp_out)
        except NFVOAgentOptions as op:
            return {'status': op.status, 'reason': op.reason, 'cp_list': op.cp_list}
        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        # debug
        logger.info('SFC Template UUID: %s\n%s', sfp_data['sfc_uuid'],
                    json.dumps(sfc_template[platform], indent=4, sort_keys=True))

        self.cache.set(sfp_data['sfc_uuid'], sfc_template)

        return {'status': OK}

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
               If there are more CPs than 1, then a message with status OPTIONS and a cp_list is replied to the
               user to inform a desirable connection point.

        :param policy_data: input arguments are:
            - sfc_uuid: the unique identifier to the SFC being composed
            - origin: if the SFC traffic source is INTERNAL or EXTERNAL
            - vnf_id: the VNF unique identifier from the NFVO when using INTERNAL traffic origin
            - resource: optional when using INTERNAL origin. Identifies the manual user input of the cp_out

        :return: OK if success, or ERROR and its reason if not, or OPTIONS and a cp_list dict
        """

        try:
            sfc_template = self.cache.get(policy_data['sfc_uuid'])
            if not sfc_template:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        if 'platform' not in policy_data:
            return {'status': OPTIONS, 'platforms': [*sfc_template]}

        platform = policy_data['platform']
        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        origin = policy_data['origin']
        vnf_id = policy_data.get('vnf_id')

        # resource means the CP_out
        cp_out = policy_data.get('resource')

        try:
            nfvo_agent.configure_traffic_src_policy(sfc_template[platform], origin, vnf_id, cp_out, database)

        except NFVOAgentOptions as op:
            return {'status': op.status, 'cp_list': op.cp_list}
        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        # debug
        logger.info('SFC Template UUID: %s\n%s', policy_data['sfc_uuid'],
                     json.dumps(sfc_template[platform], indent=4, sort_keys=True))

        self.cache.set(policy_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def configure_policies(self, policy_data):
        """Includes ACL criteria in SFC

        JSON arguments are:
            - sfc_uuid: the unique identifier of the SFC being composed
            - platform: the NFVO platform to configure policies
            - acl: a dict containing the acl criteria to be added into the SFC template

        :return: OK if success, or ERROR and its reason if not
        """

        try:
            sfc_template = self.cache.get(policy_data['sfc_uuid'])
            if not sfc_template:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        acl = policy_data['acl']

        platform = policy_data['platform']
        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        try:
            sfc_template[platform] = nfvo_agent.configure_policies(sfc_template[platform], acl)
        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        #debug
        logger.info('SFC Template UUID: %s\n%s', request.json['sfc_uuid'],
                     json.dumps(sfc_template[platform], indent=4, sort_keys=True))

        self.cache.set(policy_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def create_sfc(self, sfc_data):
        """Sends and instantiates all segments of a Multi-SFC

        If an error occurs it also calls rollback actions

        :param sfc_data: input parameters are:
            - sfc_uuid: the unique identifier of the composed SFC to be started

        :return: OK if all succeed, or ERROR and its reason
        """

        try:
            sfc_template = self.cache.get(sfc_data['sfc_uuid'])
            if not sfc_template:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        platforms = [*sfc_template]
        for platform in platforms:
            try:
                nfvo_agent = self._get_nfvo_agent_instance(platform)

            except MultiSFCException as e:
                return {'status': ERROR, 'reason': str(e)}

            response = nfvo_agent.create_sfc(sfc_template[platform], database, self, sfc_data['sfc_uuid'])
            if response['status'] != OK:
                return response

        self.cache.delete(sfc_data['sfc_uuid'])

        return {'status': OK}

    def destroy_sfc(self, sfc_id):
        """Destroy all segments of a Multi-SFC
    
        :param sfc_id: the NFVO unique identifier of the SFC
        :return: OK if succeed, or ERROR and its reason if not
        """

        try:
            # TODO Change this function call by the polymorphic version
            # needs store and retrieve data from "domains and platforms" in database
            self.tacker_agent.destroy_sfc(sfc_id, self)

        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        # remove SFC_Instance from database
        resp, sfc_instance = database.list_sfc_instances(vnffg_id=sfc_id)
        if resp == OK:
            if len(sfc_instance) > 0:
                _id = sfc_instance[0]['_id']
                database.remove_sfc_instance(_id)

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
