#!/usr/bin/env python

import logging
import json
import yaml
import os
import time
import base64
import tarfile

from click_manager import ElementManagement
from exceptions import NFVOAgentsException, NFVOAgentOptions, MultiSFCException, DatabaseException
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

        Raises
        ------
            MultiSFCException
        """

        if platform == TACKER_NFVO:
            return self.tacker_agent
        elif platform == OSM_NFVO:
            return self.osm_agent
        else:
            msg = "VNF Package '%s' platform not supported!" % platform
            logger.error(msg)
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
            try:
                vnfd = TackerAgent.vnfd_json_yaml_parser(vnfd)
            except NFVOAgentsException as e:
                return {'status': e.status, 'reason': e.reason}

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

            tar.close()

        else:
            return {'status': ERROR, 'reason': 'VNF Package unknown platform: %s' % platform}

        if vnf_type == CLICK_VNF:
            vnf_code = vnfp_data['vnf']
            vnf_file = open(dir_name + '/vnf.click', 'w')
            vnf_file.write(vnf_code)
            vnf_file.close()

        try:
            database.insert_vnf_package(category, vnfd_name, dir_id, vnf_type, platform, vnf_description)
        except DatabaseException as e:
            return {'status': e.status, 'reason': e.reason}

        return {'status': OK}

    def list_catalog(self):
        """
        List all VNFs in stored in the catalog repository

        :return: a dict of vnfs
        """
        vnfs = database.list_catalog()

        return {'vnfs': vnfs}

    def delete_package(self, pkg_id):
        """
        Remove a VNF Package from the local catalog and its repository files

        :param pkg_id: VNF Package identifier
        :return: a dict with status and error reason if it occurs
        """

        data = database.list_vnf_instances(vnf_pkg_id=pkg_id)
        if len(data) > 0:
            return {'status': ERROR, 'reason': "A VNF Instance depends on this VNF Package!"}

        try:
            catalog = database.list_catalog(pkg_id)

            if catalog:
                pkg_dir_id = catalog[0]['dir_id']

                database.remove_vnf_package(pkg_id)
                rmtree('repository/' + pkg_dir_id)

                return {'status': OK}
            else:
                return {'status': ERROR, 'reason': status[404]}

        except DatabaseException as dbe:
            return {'status': dbe.status, 'reason': dbe.reason}
        except OSError as e:
            logger.error("%s '%s'", e.strerror, e.filename)
            return {'status': ERROR, 'reason': e.strerror}

    def list_vnfs(self):
        """List all instantiated VNFs in NFVO"""

        try:
            data = self.tacker_agent.list_vnfs()
            osm_data = self.osm_agent.list_vnfs()

        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        data.extend(osm_data)

        return {'status': OK, 'vnfs': data}

    def create_vnf(self, vnf_pkg_id, issubprocess=False):
        """ Instantiates a given VNF and initializes its function in NFVO

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

        catalog = db.list_catalog(vnf_pkg_id=vnf_pkg_id)

        if not catalog:
            return {'status': ERROR, 'reason': 'VNF Package not found!'}

        dir_id = catalog[0]['dir_id']
        vnfd_name = catalog[0]['vnfd_name']
        vnf_type = catalog[0]['vnf_type']
        platform = catalog[0]['platform']
        vnfp_dir = 'repository/%s' % dir_id

        vnf_name = str(vnfd_name).replace('vnfd', 'vnf')

        try:
            nfvo_agent = self._get_nfvo_agent_instance(platform)

            response = nfvo_agent.create_vnf(vnfp_dir, vnfd_name, vnf_name)

        except NFVOAgentsException as ex:
            return {'status': ex.status, 'reason': ex.reason}
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        logger.info('VNF %s is active with IP %s', response['vnf_id'], response['vnf_ip'])

        try:
            db.insert_vnf_instance(vnf_pkg_id, response['vnfd_id'], response['vnf_id'])

        # Rollback actions if database inserting fails
        except DatabaseException as dbe:
            error_message = 'Database error: %s' % dbe.reason

            logger.error("Executing rollback actions...\n%s", error_message)

            try:
                nfvo_agent.destroy_vnf(response['vnf_id'])
                logger.info("Rollback done!")

            except NFVOAgentsException as e:
                error_message = ' '.join([error_message, e.reason])
                logger.error(error_message)

            return {'status': ERROR, 'reason': error_message}

        # TODO Maybe configure VNF functions could be in another function (e.g. init_vnfs)
        if vnf_type == CLICK_VNF:
            function_path = 'repository/%s/vnf.click' % dir_id
            with open(function_path) as function_file:
                function_data = function_file.read()

            try:
                self.init_click(response['vnf_id'], response['vnf_ip'], function_data)

            except MultiSFCException as e:
                return {'status': ERROR, 'reason': str(e)}

            logger.info('VNF %s function initialized', response['vnf_id'])

        logger.info('VNF %s instantiated successfully', response['vnf_id'])

        # return instantiated vnf data
        response['status'] = OK
        return response

    def destroy_vnf(self, vnf_id):
        """Destroys a given VNF in NFVO

        :param vnf_id: the NFVO VNF's ID
        :return: OK if success, or ERROR and its reason if not
        """

        try:
            vnf_instance = database.list_vnf_instances(vnf_id=vnf_id)
            vnf_pkg = database.list_catalog(vnf_pkg_id=vnf_instance[0]['vnf_pkg_id'])

            platform = vnf_pkg[0]['platform']
            nfvo_agent = self._get_nfvo_agent_instance(platform)

            logger.info('Destroying VNF Instance %s', vnf_id)
            nfvo_agent.destroy_vnf(vnf_id)
            logger.info('VNF Instance %s destroyed successfully', vnf_id)

            database.remove_vnf_instance(vnf_instance[0]['_id'])

        except IndexError:
            return {'status': ERROR, 'reason': 'VNF not found in database!'}
        except (DatabaseException, NFVOAgentsException) as e:
            return {'status': e.status, 'reason': e.reason}
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        return {'status': OK}

    def init_click(self, vnf_id, vnf_ip, click_function):
        """Once Click VNF VM is running, initialize all tasks.

        Wait at least 15 seconds until Click VNF is ready to initialize its tasks
        The waiting timeout is up to 30 seconds before trying to write and start the function
        Each test is executed on port TCP 8000 using intervals of 2 seconds, in order to not break the Click HTTP Server

        Raises
        ------
            MultiSFCException
        """

        logger.info('VNF %s Initializing click dependencies' % vnf_id)

        # Wait until all vnf-level dependencies are fully loaded
        # TODO: What is the best way to determine this sleep time? It may change from one VIM to another.
        # Use 15 seconds when click takes much time to initialize, because the Click-on-OSv HTTP Server
        # breaks if a connection is done before all its dependencies are fully loaded.
        time.sleep(15)
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
        #         logger.error('Something went wrong in init_click function: %s' % e)

        try:
            # send function to VNF VM
            response = self.click_em.write_function(vnf_ip, click_function)
            # TODO: It returns status_core=200 even that the function has been started or not
            # Maybe look at the response "text" parameter
            if response.status_code != 200:
                message = 'Unable to write click function. %s' % response.text
                logger.error(message)
                raise MultiSFCException(message)

            # start VNF function
            response = self.click_em.start_function(vnf_ip)
            # TODO: It returns status_core=200 even that the function has been started or not
            # Maybe look at the response "text" parameter
            if response.status_code != 200:
                message = 'Unable to start click function. %s' % response.text
                logger.error(message)
                raise MultiSFCException(message)

        except Exception as e:
            message = 'VNF %s functions not initialized: %s' % (vnf_id, str(e))
            logger.error(message)
            raise MultiSFCException(message)

    def get_vnf_package(self, vnf_id):
        """Retrieves a VNF Package stored in Catalog from a given NFVO's VNF ID

        :param vnf_id:
        :return:
        """

        try:
            data = database.list_vnf_instances(vnf_id=vnf_id)
        except DatabaseException as e:
            return {'status': e.status, 'reason': e.reason}

        if data:
            return {'status': OK, 'package': data[0]}
        else:
            return {'status': ERROR, 'reason': 'VNF Package not found in Catalog!'}

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

        :return: a unique identifier string
        """

        sfc_uuid = unique_id()
        self.cache.set(sfc_uuid, {})

        return {'sfc_uuid': sfc_uuid}

    def compose_sfp(self, sfp_data):
        """Performs VNF Chaining in the SFC Template.

        This function stands for VNF Chaining and its requirements for CPs and VLs using the SFC Template.
        The following rules are taken into account:
        - cp_in: chooses the cp_in according to the same network of the previous cp_out.
                 If the VNF is the first one, then the first CP is chosen (disregarding the management interface)
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

        try:
            catalog = database.list_catalog(vnf_pkg_id)

            vnfd_name = catalog[0]['vnfd_name']
            vnf_pkg_dir = catalog[0]['dir_id']
            platform = catalog[0]['platform']

            nfvo_agent = self._get_nfvo_agent_instance(platform)

            if platform not in sfc_template:
                sfc_template[platform] = deepcopy(nfvo_agent.get_sfc_template())

            sfc_template[platform] = nfvo_agent.compose_sfp(sfc_template[platform], vnfd_name, vnf_pkg_dir,
                                                            database, cp_out)

        except IndexError:
            return {'status': ERROR, 'reason': 'VNF Package %s not found!' % vnf_pkg_id}

        except NFVOAgentOptions as op:
            return {'status': op.status, 'reason': op.reason, 'cp_list': op.cp_list}

        except (NFVOAgentsException, DatabaseException) as e:
            return {'status': e.status, 'reason': e.reason}

        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        # debug
        logger.debug('SFC Template UUID: %s\n%s', sfp_data['sfc_uuid'],
                    nfvo_agent.dump_sfc_descriptor(sfc_template[platform]))

        self.cache.set(sfp_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def include_classifier_policy(self, policy_data):
        """Includes ACL criteria according to INTERNAL or EXTERNAL traffic source

        INTERNAL traffic is sourced from VNFs managed by NFVO, while EXTERNAL traffic is sourced from everything
        out from NFVO networks.

        One important rule is applied:
            1. NFVO's network_name from the origin VNF CP must be the same as the input CP of the first VNF in the chain.
               If there are more CPs than 1, then a message with status OPTIONS and a cp_list is replied to the
               user to inform a desirable connection point.

        :param policy_data: input arguments are:
            - sfc_uuid: the unique identifier to the SFC being composed
            - origin: if the SFC traffic source is INTERNAL or EXTERNAL
            - src_id: the VNF or VNF Package unique identifier from the NFVO when using INTERNAL traffic origin
            - resource: optional when using INTERNAL origin. Identifies the manual user input of the source cp_out

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
        src_id = policy_data.get('src_id')

        # resource means the CP_out
        cp_out = policy_data.get('resource')

        try:
            if platform == TACKER_NFVO:
                vnf = database.list_vnf_instances(vnf_id=src_id)
                if not vnf:
                    raise MultiSFCException("VNF Instance not found in database.")
                vnfp = database.list_catalog(vnf_pkg_id=vnf[0]['vnf_pkg_id'])

            else:  # here only remained the OSM_NFVO which was validated by the above code
                vnfp = database.list_catalog(vnf_pkg_id=src_id)

            vnfp_platform = vnfp[0]['platform']

            if vnfp_platform != platform and origin == INTERNAL:
                raise NFVOAgentsException(ERROR, "Choose a VNF from '%s' platform!" % platform)

            sfc_template[platform] = nfvo_agent.configure_traffic_src_policy(
                                            sfc_template[platform], origin, src_id, cp_out, database)
        except NFVOAgentOptions as op:
            return {'status': op.status, 'cp_list': op.cp_list}
        except (NFVOAgentsException, DatabaseException) as e:
            return {'status': e.status, 'reason': e.reason}

        # debug
        logger.debug('SFC Template UUID: %s\n%s', policy_data['sfc_uuid'],
                    nfvo_agent.dump_sfc_descriptor(sfc_template[platform]))

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

            sfc_template[platform] = nfvo_agent.configure_policies(sfc_template[platform], acl)

        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        # debug
        logger.debug('SFC Template UUID: %s\n%s', request.json['sfc_uuid'],
                     nfvo_agent.dump_sfc_descriptor(sfc_template[platform]))

        self.cache.set(policy_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def create_sfc(self, sfc_data):
        """Sends and instantiates all segments of a Multi-SFC

        If an error occurs it also calls rollback actions

        :param sfc_data:
            input parameters are:

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
        sfc_name = sfc_data.get('sfc_name')
        if sfc_name:
            sfc_name = sfc_name.replace(' ', '')
        else:
            sfc_name = unique_id()

        for platform in platforms:
            try:
                nfvo_agent = self._get_nfvo_agent_instance(platform)

                sfc = nfvo_agent.create_sfc(sfc_template[platform], database, self, sfc_data['sfc_uuid'], sfc_name)

            except (NFVOAgentsException, DatabaseException) as ex:
                return {'status': ex.status, 'reason': ex.reason}
            except MultiSFCException as e:
                return {'status': ERROR, 'reason': str(e)}

            # Rollback in case of error on inserting in database
            try:
                database.insert_sfc_instance(sfc['vnf_instances'], sfc['nsd_id'], sfc['ns_id'], sfc_name, platform)
            # Rollback actions
            except DatabaseException as dbe:
                # this function raises an NFVOAgentsException and don't need to be caught,
                # either way, the code after it won't run
                # self.destroy_vnffg(vnffg_id)
                try:
                    nfvo_agent.destroy_sfc(sfc['ns_id'])
                except NFVOAgentsException as e:
                    dbe.reason = ' '.join([dbe.reason, e.reason])

                return {'status': dbe.status, 'reason': dbe.reason}

            logger.info("SFC %s instantiated successfully!", sfc['ns_id'])

        self.cache.delete(sfc_data['sfc_uuid'])

        return {'status': OK}

    def destroy_sfc(self, sfc_id):
        """Destroy all segments of a Multi-SFC
    
        :param sfc_id: the NFVO unique identifier of the SFC
        :return: OK if succeed, or ERROR and its reason if not
        """

        try:
            sfc = database.list_sfc_instances(ns_id=sfc_id)
            if not sfc:
                raise MultiSFCException("SFC id %s cannot be destroyed. Not found in database." % sfc_id)

            nfvo_agent = self._get_nfvo_agent_instance(sfc[0]['platform'])

            nfvo_agent.destroy_sfc(sfc_id, self)

            # remove SFC_Instance from database
            _id = sfc[0]['_id']
            database.remove_sfc_instance(_id)

        except (NFVOAgentsException, DatabaseException) as e:
            return {'status': e.status, 'reason': e.reason}
        except MultiSFCException as ex:
            return {'status': ERROR, 'reason': str(ex)}

        return {'status': OK}

    def list_sfcs(self):
        """Retrieves all SFCs from Tacker and OSM"""

        try:
            data = self.tacker_agent.list_sfcs()
            osm_data = self.osm_agent.list_sfcs()
        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}

        data.extend(osm_data)

        return {'status': OK, 'sfcs': data}
