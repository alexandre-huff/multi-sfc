#!/usr/bin/env python

import logging
import json
import sys
import yaml
import os
import base64
import tarfile

from builtins import AttributeError
from queue import Queue
from threading import Thread
from click_manager import ElementManagement
from em.tunnel_manager import VXLANTunnel, IPSecTunnel, GRETunnel
from exceptions import NFVOAgentsException, NFVOAgentOptions, MultiSFCException, DatabaseException, \
    DomainDataException, VIMAgentsException
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

DOMAIN_CATALOG = 'domain-config.yaml'


class Core:

    def __init__(self):
        # self.database = DatabaseConnection()
        self.cache = MemcachedCache()
        self.click_em = ElementManagement()

        self._config_data = self._parse_domain_config_file()
        self._instantiate_nfvo_agents()
        self._domain_catalog = self._parse_domain_catalog_data()

    def _parse_domain_config_file(self):
        """Parses the domain config file

        The config data is useful when there is a need to iterate over all NFVOs of each domain

        :return: a dict containing the config data
        """
        raw_data = None
        try:
            with open(DOMAIN_CATALOG, 'r') as config:
                raw_data = config.read()
        except FileNotFoundError:
            logger.critical("Missing %s file!", DOMAIN_CATALOG)
            exit(1)

        config_data = yaml.full_load(raw_data)

        tacker_keys = ['id', 'name', 'platform', 'auth_url', 'username', 'password', 'tenant-name',
                       'vim-name', 'vim-username', 'vim-password', 'vim-type', 'tunnel']

        osm_keys = ['id', 'name', 'platform', 'host', 'username', 'password', 'tenant-name',
                    'vim-name', 'vim-username', 'vim-password', 'vim-type', 'tunnel']

        try:
            for domain in config_data['domains']:

                for nfvo in domain['nfvos']:
                    if nfvo['platform'] == TACKER_NFVO:
                        nfvo_keys = tacker_keys
                    else:
                        nfvo_keys = osm_keys

                    missing_keys = [k for k in nfvo_keys if k not in nfvo.keys()]
                    if missing_keys:
                        # removing the '[' and ']' chars
                        missing_keys = str(missing_keys)[1:-1]
                        logger.critical("Missing key(s) %s in 'nfvos:' at %s in %s file", missing_keys,
                                        domain['id'], DOMAIN_CATALOG)
                        exit(1)

        except KeyError as e:
            logger.critical("Missing key %s in file %s", str(e), DOMAIN_CATALOG)
            exit(1)

        return config_data

    def _parse_domain_catalog_data(self):
        """Parses the domain config data in a domain catalog

        The domain catalog is useful to access the domain catalog information directly.

        :return: a dict containing the domain catalog
        """

        domain_catalog = {}

        for domain in self._config_data['domains']:
            domain_id = domain['id']
            domain_catalog[domain_id] = {'name': domain['name']}

            for nfvo in domain['nfvos']:
                nfvo_id = nfvo['id']

                # just copy the nfvo reference to have less memory usage
                # don't remove the id of nfvo_data. Remember, it is a reference copy!
                nfvo_data = {nfvo_id: nfvo}

                domain_catalog[domain_id].update(nfvo_data)

        return domain_catalog

    def _instantiate_nfvo_agents(self):
        for domain in self._config_data['domains']:
            for nfvo in domain['nfvos']:
                platform = nfvo['platform']

                if platform == TACKER_NFVO:
                    nfvo['nfvo_agent'] = TackerAgent(nfvo['auth_url'], nfvo['username'], nfvo['password'],
                                                     nfvo['tenant-name'], nfvo['vim-name'], nfvo['vim-username'],
                                                     nfvo['vim-password'], domain['id'], domain['name'],
                                                     nfvo['id'], nfvo['name'])

                elif platform == OSM_NFVO:
                    nfvo['nfvo_agent'] = OSMAgent(nfvo['host'], nfvo['username'], nfvo['password'],
                                                  nfvo['tenant-name'], nfvo['vim-name'], nfvo['vim-username'],
                                                  nfvo['vim-password'], domain['id'], domain['name'],
                                                  nfvo['id'], nfvo['name'])

                else:
                    msg = "NFV platform '%s' not supported! Check %s file." % (platform, DOMAIN_CATALOG)
                    logger.critical(msg)
                    exit(1)

    def _get_nfvo_agent_instance(self, domain_id, nfvo_id):
        """
        Returns the NFVO Agent instance based on both domain id and nfvo instance id

        :param domain_id: the domain ID from a VNF Package stored in Catalog
        :param nfvo_id: the NFVO ID from a VNF Package stored in Catalog
        :return: an instance of NFVO Agent
        """

        for domain in self._config_data['domains']:
            for nfvo in domain['nfvos']:
                if domain['id'] == domain_id and nfvo['id'] == nfvo_id:

                    return nfvo['nfvo_agent']

    def _get_domains_and_nfvos(self, platform, domain_id):
        """Retrieves a list of domains with their NFVOs from domain catalog according to a given platform

        :param platform: a platform type (i.e. NFVO)
        :param domain_id: the id of a domain stored in catalog domain or in vnf catalog database, or ANY for all domains

        :return: a list with domain ids and names each containing a list of NFVO ids and names
        """

        domain_nfvo_data = {'domains': []}
        for domain in self._config_data['domains']:
            nfvos = []
            for nfvo in domain['nfvos']:
                if nfvo['platform'] == platform:
                    nfvos.append({
                        'nfvo_id': nfvo['id'],
                        'nfvo_name': nfvo['name']
                    })
            if (nfvos and domain_id == ANY) or (nfvos and domain_id == domain['id']):
                domain_data = {
                    'domain_id': domain['id'],
                    'domain_name': domain['name'],
                    'nfvos': nfvos
                }
                domain_nfvo_data['domains'].append(domain_data)

        return domain_nfvo_data

    def include_package(self, vnfp_data):
        """
        Includes a VNF Package in the VNF Catalog and in the file repository

        :return: an 'OK' dict status or error and its reason if not
        """
        # TODO: consider also upload the VNF Image to the Tacker and OSM

        vnfd = vnfp_data['vnfd']
        descriptor = json.loads(vnfp_data['descriptor'])

        category = descriptor['category']
        vnf_type = descriptor['type']
        platform = descriptor['platform']
        vnf_description = descriptor['description']
        tunnel_type = descriptor.get('tunnel')
        domain_id = vnfp_data.get('domain_id')
        nfvo_id = vnfp_data.get('nfvo_id')

        if not domain_id:
            domain_data = self._get_domains_and_nfvos(platform, ANY)
            return {
                'status': OPTIONS,
                'reason': "Inform the Domain and Platform required to run this VNF Package",
                'domain_data': domain_data
            }
        domain_id = domain_id.replace(' ', '')

        if nfvo_id:
            nfvo_id = nfvo_id.replace(' ', '')
        else:
            nfvo_id = ANY

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
            database.insert_vnf_package(category, vnfd_name, dir_id, vnf_type, domain_id,
                                        nfvo_id, platform, vnf_description, tunnel_type)
        except DatabaseException as e:
            return {'status': e.status, 'reason': e.reason}

        return {'status': OK}

    def list_catalog(self):
        """
        List all VNFs stored in the catalog repository

        :return: a dict of vnfs
        """
        vnfs = database.list_catalog()
        for vnf in vnfs:
            domain_id = vnf['domain_id']
            nfvo_id = vnf['nfvo_id']

            try:
                domain_name = self._domain_catalog[domain_id]['name']
            except KeyError:
                domain_name = ANY

            try:
                nfvo_name = self._domain_catalog[domain_id][nfvo_id]['name']
            except KeyError:
                nfvo_name = ANY

            domain_data = {
                'domain_name': domain_name,
                'nfvo_name': nfvo_name
            }
            vnf.update(domain_data)

        return {'vnfs': vnfs}

    def list_domain_nfvo_vnfs(self, domain_id, nfvo_id):
        platform = self._domain_catalog[domain_id][nfvo_id]['platform']

        vnfs = database.list_catalog(platform=platform,
                                     domain_id={"$in": [domain_id, "ANY"]},
                                     nfvo_id={"$in": [nfvo_id, "ANY"]})

        for vnf in vnfs:
            domain_id = vnf['domain_id']
            nfvo_id = vnf['nfvo_id']

            try:
                domain_name = self._domain_catalog[domain_id]['name']
            except KeyError:
                domain_name = ANY

            try:
                nfvo_name = self._domain_catalog[domain_id][nfvo_id]['name']
            except KeyError:
                nfvo_name = ANY

            domain_data = {
                'domain_name': domain_name,
                'nfvo_name': nfvo_name
            }
            vnf.update(domain_data)

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
        """List all instantiated VNFs in all domain NFVOs"""

        data = []
        for domain in self._config_data['domains']:
            for nfvo in domain['nfvos']:
                nfvo_agent = nfvo['nfvo_agent']

                try:
                    vnfs = nfvo_agent.list_vnfs()
                    # avoids to show a same vnf more than once in case of
                    # using a same NFVO using different VIMs in domain catalog
                    for vnf in vnfs:
                        if vnf not in data:
                            data.extend([vnf])

                except NFVOAgentsException as e:
                    return {'status': e.status, 'reason': e.reason}

        return {'status': OK, 'vnfs': data}

    def create_vnf(self, vnf_pkg_data, queue=None):
        """ Instantiates a given VNF and initializes its function in NFVO

        :param vnf_pkg_data: used to instantiate VNFs based on vnfp_id, domain_id, and nfvo_id
        :param queue: states that this function is running in a thread and should put the response in that queue
                      instead of returning it using the regular "return" primitive
        :return: a dict containing OK, vnfd_id, vnf_id and vnf_ip if success, or ERROR and its reason if not
        """
        # PERFORMANCE TEST and DEMO mode: uncomment the line below in order to use fake_tacker.py
        # click_function = None

        catalog = database.list_catalog(vnf_pkg_id=vnf_pkg_data['vnfp_id'])

        if not catalog:
            response = {'status': ERROR, 'reason': 'VNF Package not found!'}
            if queue:
                queue.put(response)
                return
            return response

        dir_id = catalog[0]['dir_id']
        vnfd_name = catalog[0]['vnfd_name']
        vnf_type = catalog[0]['vnf_type']
        platform = catalog[0]['platform']
        domain_id = catalog[0]['domain_id'] if vnf_pkg_data.get('domain_id') is None else vnf_pkg_data.get('domain_id')
        nfvo_id = catalog[0]['nfvo_id'] if vnf_pkg_data.get('nfvo_id') is None else vnf_pkg_data.get('nfvo_id')
        vnfp_id = vnf_pkg_data['vnfp_id']
        vnfp_dir = 'repository/%s' % dir_id

        vnf_name = str(vnfd_name).replace('vnfd', 'vnf')

        domain_id, nfvo_id = self.validate_platform_domain_nfvo(platform, domain_id, nfvo_id)

        try:
            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            response = nfvo_agent.create_vnf(vnfp_dir, vnfd_name, vnf_name)

        except NFVOAgentsException as ex:
            response = {'status': ex.status, 'reason': ex.reason}
            if queue:
                queue.put(response)
                return
            return response

        except MultiSFCException as e:
            response = {'status': ERROR, 'reason': str(e)}
            if queue:
                queue.put(response)
                return
            return response

        logger.info('VNF %s is active with IP %s', response['vnf_id'], response['vnf_ip'])

        try:
            database.insert_vnf_instance(vnfp_id, domain_id, nfvo_id, response['vnfd_id'], response['vnf_id'])

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

            response = {'status': ERROR, 'reason': error_message}
            if queue:
                queue.put(response)
                return
            return response

        # TODO Configuring VNF functions could be moved to a particular function (e.g. init_vnfs)
        if vnf_type == CLICK_VNF:
            function_path = 'repository/%s/vnf.click' % dir_id
            with open(function_path) as function_file:
                function_data = function_file.read()

            try:
                self.init_click(response['vnf_id'], response['vnf_ip'], function_data)

            except MultiSFCException as e:
                response = {'status': ERROR, 'reason': str(e)}
                if queue:
                    queue.put(response)
                    return
                return response

            logger.info('VNF %s function initialized', response['vnf_id'])

        logger.info('VNF %s instantiated successfully', response['vnf_id'])

        # return instantiated vnf data
        response['status'] = OK
        if queue:
            response['vnfd_name'] = vnfd_name
            queue.put(response)
            return
        return response

    def destroy_vnf(self, vnf_id, queue=None):
        """Destroys a given VNF in its NFVO

        :param vnf_id: the NFVO VNF's ID
        :param queue: states that this function is running in a thread and should put the response in that queue
                      instead of returning it using the regular "return" primitive

        :return: OK if success, or ERROR and its reason if not
        """
        response = None

        try:
            vnf_instance = database.list_vnf_instances(vnf_id=vnf_id)

            domain_id = vnf_instance[0]['domain_id']
            nfvo_id = vnf_instance[0]['nfvo_id']
            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            logger.info('Destroying VNF Instance %s', vnf_id)
            nfvo_agent.destroy_vnf(vnf_id)
            logger.info('VNF Instance %s destroyed successfully', vnf_id)

            database.remove_vnf_instance(vnf_instance[0]['_id'])

        except IndexError:
            response = {'status': ERROR, 'reason': 'VNF not found in database!'}
        except (DatabaseException, NFVOAgentsException) as e:
            response = {'status': e.status, 'reason': e.reason}
        except MultiSFCException as e:
            response = {'status': ERROR, 'reason': str(e)}

        if response is None:
            response = {'status': OK}
        else:
            logger.error('Unable to destroy VNF instance id %s, reason: %s', vnf_id, response['reason'])

        if queue:
            queue.put(response)
            return
        return response

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

    # def get_vnf_package(self, vnf_id):
    #     """Retrieves a VNF Package stored in Catalog from a given NFVO's VNF ID
    #
    #     :param vnf_id:
    #     :return:
    #     """
    #
    #     try:
    #         data = database.list_vnf_instances(vnf_id=vnf_id)
    #     except DatabaseException as e:
    #         return {'status': e.status, 'reason': e.reason}
    #
    #     if data:
    #         return {'status': OK, 'package': data[0]}
    #     else:
    #         return {'status': ERROR, 'reason': 'VNF Package not found in Catalog!'}

    def get_domain_catalog(self):
        """Retrieves information of all domains in domain catalog

        :return information of all domain such as domain id and name, nfvo id and name, vim name,
        tenant name, and tunnel type
        """
        domain_data = []
        for domain in self._config_data['domains']:

            for nfvo in domain['nfvos']:
                data = {
                    'domain_id': domain['id'],
                    'domain_name': domain['name'],
                    'nfvo_id': nfvo['id'],
                    'nfvo_name': nfvo['name'],
                    'tenant_name': nfvo['tenant-name'],
                    'vim_name': nfvo['vim-name'],
                    'tunnel': nfvo['tunnel']
                }
                domain_data.append(data)
        return domain_data

    def list_available_acl(self, sfc_uuid):
        """Retrieves the NFVO classifier ACL of the first SFC segment"""
        sfc_segments = self.cache.get(sfc_uuid)
        if sfc_segments is None:
            return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        domain_id = sfc_segments[0]['domain_id']
        nfvo_id = sfc_segments[0]['nfvo_id']

        try:
            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        acl_criterias = nfvo_agent.get_available_policies()

        return {'acl': acl_criterias}

    def create_sfc_uuid(self):
        """Retrieves an unique identifier in order to compose a new SFC

        :return: a unique identifier string
        """

        sfc_uuid = unique_id()
        self.cache.set(sfc_uuid, [])

        return {'sfc_uuid': sfc_uuid}

    def validate_platform_domain_nfvo(self, platform, domain_id, nfvo_id):
        """
        Validates if the domain_id and nfvo_id exist in Domain Catalog and if they correspond to the informed platform

        This function also tries to select automatically both domain and nfvo, based on the informed platform

        :param platform: the platform type
        :param domain_id:
        :param nfvo_id:
        :return: a domain_id and nfvo_id

        Raises
        ------
            DomainDataException
                In case of having multiple choice of domains or nfvos

            MultiSFCException
                In case domain, nfvo, and platform don't match with domain catalog data
        """
        if domain_id == ANY or nfvo_id == ANY:

            domain_data = self._get_domains_and_nfvos(platform, domain_id)
            # trying to select domain and nfvo automatically
            if len(domain_data['domains']) == 1:
                domain_id = domain_data['domains'][0]['domain_id']

                if len(domain_data['domains'][0]['nfvos']) == 1:
                    nfvo_id = domain_data['domains'][0]['nfvos'][0]['nfvo_id']

            if domain_id == ANY:
                raise DomainDataException(OPTIONS, "Inform a Domain and a Platform to run this VNF", domain_data)

            if nfvo_id == ANY:
                reason = "Inform a Platform Instance to run this VNF in domain '%s'" \
                         % self._domain_catalog[domain_id]['name']
                raise DomainDataException(OPTIONS, reason, domain_data)

        if self._domain_catalog[domain_id][nfvo_id]['platform'] != platform:
            msg = "Domain '%s' , NFVO '%s', and Platform '%s' don't match!" % (domain_id, nfvo_id, platform)
            logger.error(msg)
            raise MultiSFCException(msg)

        return domain_id, nfvo_id

    def validate_sfc_domain_nfvo_vnf_package(self, vnf_pkg_obj, domain_id, nfvo_id):
        """Validates if a VNF Package can be instantiated in the corresponding domain and nfvo

        This function compares if information provided in domain_id and nfvo_id matches in VNF Package catalog
        and in Domain Catalog. It validates input mistakes from the user and post modifications in domain-config file.
        Post modifications can happen when a VNF Package has been stored in database before a domain-config file
        modification, leading to information conflicts

        :param vnf_pkg_obj: a VNF Package object from VNF Catalog
        :param domain_id:
        :param nfvo_id:

        Raises
        ------
            MultiSFCException
        """
        try:
            _ = self._domain_catalog[domain_id]
            _ = self._domain_catalog[domain_id][nfvo_id]
        except KeyError as e:
            msg = "Provided information mismatch from Domain Catalog: %s" % str(e)
            logger.error(msg)
            raise MultiSFCException(msg)

        if vnf_pkg_obj is None:
            raise MultiSFCException("Invalid VNF Package!")

        pkg_domain_id = vnf_pkg_obj['domain_id']
        pkg_nfvo_id = vnf_pkg_obj['nfvo_id']
        pkg_platform = vnf_pkg_obj['platform']

        if pkg_platform != self._domain_catalog[domain_id][nfvo_id]['platform']:
            raise MultiSFCException("Choose a VNF Package with '%s' platform!"
                                    % self._domain_catalog[domain_id][nfvo_id]['platform'])

        if pkg_domain_id != ANY and pkg_domain_id != domain_id:
            raise MultiSFCException("Choose a VNF Package from Domain '%s'!"
                                    % self._domain_catalog[domain_id]['name'])

        if pkg_nfvo_id != ANY and pkg_nfvo_id != nfvo_id:
            raise MultiSFCException("Choose a VNF Package from Platform Instance '%s'!"
                                    % self._domain_catalog[domain_id][nfvo_id]['name'])

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
            - domain_id:
            - nfvo_id:
            - cp_out: not required, but can be used as a manually user input

        :return: OK if success, or ERROR and its reason if not, or OPTIONS and a cp_list dict
        """

        try:
            sfc_segment_templates = self.cache.get(sfp_data['sfc_uuid'])
            if sfc_segment_templates is None:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        cp_out = sfp_data.get('cp_out')

        vnf_pkg_id = sfp_data['vnf_pkg_id']

        try:
            catalog = database.list_catalog(vnf_pkg_id)

            vnfd_name = catalog[0]['vnfd_name']
            vnf_pkg_dir = catalog[0]['dir_id']
            domain_id = sfp_data.get('domain_id')
            nfvo_id = sfp_data.get('nfvo_id')

            self.validate_sfc_domain_nfvo_vnf_package(catalog[0], domain_id, nfvo_id)

            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            index = None
            for segment in range(len(sfc_segment_templates)):
                if sfc_segment_templates[segment]['domain_id'] == domain_id \
                        and sfc_segment_templates[segment]['nfvo_id'] == nfvo_id:
                    index = segment
                    break

            if index is None:
                segment_data = {
                    'domain_id': domain_id,
                    'nfvo_id': nfvo_id,
                    'sfc_template': deepcopy(nfvo_agent.get_sfc_template())
                }
                index = len(sfc_segment_templates)
                sfc_segment_templates.append(segment_data)

            sfc_segment_templates[index]['sfc_template'] = \
                nfvo_agent.compose_sfp(sfc_segment_templates[index]['sfc_template'],
                                       vnfd_name, vnf_pkg_dir, database, cp_out)

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
                     nfvo_agent.dump_sfc_descriptor(sfc_segment_templates[index]['sfc_template']))

        self.cache.set(sfp_data['sfc_uuid'], sfc_segment_templates)

        return {'status': OK}

    def get_sfc_traffic_origin(self, sfc_uuid):
        """Retrieves fields and eligible VNF information for traffic incoming of the first SFC segment"""

        sfc_segments = self.cache.get(sfc_uuid)
        if sfc_segments is None:
            return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        domain_id = sfc_segments[0]['domain_id']
        nfvo_id = sfc_segments[0]['nfvo_id']

        nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

        fields, src_vnfs = nfvo_agent.get_sfc_traffic_origin(self)

        return {
            'status': OK,
            'fields': fields,
            'vnfs': src_vnfs
        }

    def include_classifier_policy(self, policy_data):
        """Includes ACL criteria according to INTERNAL or EXTERNAL traffic source in the first SFC segment

        INTERNAL traffic is sourced from VNFs managed by NFVO, while EXTERNAL traffic is sourced from everything
        out from NFVO networks.

        One important rule is applied:
            1. NFVO's network_name from the origin VNF CP must be the same as the input CP of the first VNF
               in the chain.
               If there are more CPs than 1, then a message with status OPTIONS and a cp_list is replied to the
               user to inform a desirable connection point.

        :param policy_data: input arguments are:

            :sfc_uuid: the unique identifier to the SFC being composed
            :origin: if the SFC traffic source is INTERNAL or EXTERNAL
            :src_id: the VNF or VNF Package unique identifier from the NFVO when using INTERNAL traffic origin
            :resource: optional when using INTERNAL origin. Identifies the manual user input of the source cp_out

        :return: OK if success, or ERROR and its reason if not, or OPTIONS and a cp_list dict
        """

        try:
            sfc_template = self.cache.get(policy_data['sfc_uuid'])
            if not sfc_template:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        domain_id = sfc_template[0]['domain_id']
        nfvo_id = sfc_template[0]['nfvo_id']

        try:
            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        origin = policy_data['origin']
        src_id = policy_data.get('src_id')
        # resource means the CP_out
        cp_out = policy_data.get('resource')

        if origin == INTERNAL:

            # getting the VNF Package information from src_id
            vnf = database.list_vnf_instances(vnf_id=src_id)
            try:
                vnfp = database.list_catalog(vnf_pkg_id=vnf[0]['vnf_pkg_id'])[0]
            except (IndexError, KeyError):
                try:
                    vnfp = database.list_catalog(vnf_pkg_id=src_id)[0]
                except IndexError:
                    vnfp = None

            try:
                self.validate_sfc_domain_nfvo_vnf_package(vnfp, domain_id, nfvo_id)
            except MultiSFCException as e:
                return {'status': ERROR, 'reason': str(e)}

        try:
            sfc_template[0]['sfc_template'] = nfvo_agent.configure_traffic_src_policy(
                sfc_template[0]['sfc_template'], origin, src_id, cp_out, database)

        except NFVOAgentOptions as op:
            return {'status': op.status, 'cp_list': op.cp_list}
        except (NFVOAgentsException, DatabaseException) as e:
            return {'status': e.status, 'reason': e.reason}

        # debug
        logger.debug('SFC Template UUID: %s\n%s', policy_data['sfc_uuid'],
                     nfvo_agent.dump_sfc_descriptor(sfc_template[0]['sfc_template']))

        self.cache.set(policy_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def configure_policies(self, policy_data):
        """Includes ACL criteria on the first SFC segment

        JSON arguments are:
            - sfc_uuid: the unique identifier of the SFC being composed
            - acl: a dict containing the acl criteria to be added into the SFC template

        :return: OK if success, or ERROR and its reason if not
        """
        try:
            sfc_template = self.cache.get(policy_data['sfc_uuid'])
            if not sfc_template:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        policies = policy_data['policies']

        # configuring policies of SFC incoming traffic
        domain_id = sfc_template[0]['domain_id']
        nfvo_id = sfc_template[0]['nfvo_id']

        try:
            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            sfc_template[0]['sfc_template'] = nfvo_agent.configure_policies(sfc_template[0]['sfc_template'],
                                                                            policies)

        except NFVOAgentsException as e:
            return {'status': e.status, 'reason': e.reason}
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        # debug
        logger.debug('SFC Template UUID: %s\n%s', request.json['sfc_uuid'],
                     nfvo_agent.dump_sfc_descriptor(sfc_template[0]['sfc_template']))

        self.cache.set(policy_data['sfc_uuid'], sfc_template)

        return {'status': OK}

    def parse_segment_classifier_policy(self, policy, input_platform, output_platform):
        """ Maps an ACL type from one NFV Orchestrator to the same ACL on another NFV Orchestrator

        :param policy: a dict containing the classifier policy (ACL name) as the key and its value
        :param input_platform: the platform name of the policy param (e.g. tacker, osm)
        :param output_platform: the platform name of the policy to be parsed
        :return: a dict with the parsed classifier policy of the output platform, or None if the policy was not found
        """
        policy_mapping = {
            # Syntax 'platform': ['protocol', src_ip', 'dst_ip', 'src_port', 'dst_port']
            TACKER_NFVO: ['ip_proto', 'ip_src_prefix', 'ip_dst_prefix', 'source_port_range', 'destination_port_range'],
            OSM_NFVO: ['ip-proto', 'source-ip-address', 'destination-ip-address', 'source-port', 'destination-port']
        }

        key = [*policy][0]
        value = policy[key]

        try:
            index = policy_mapping[input_platform].index(key)
        except ValueError:
            return None

        if input_platform == TACKER_NFVO:

            if key in ('ip_src_prefix', 'ip_dst_prefix'):  # IP
                value = value.split(sep='/')[0]
            elif key in ('source_port_range', 'destination_port_range'):  # PORTS
                value = value.split(sep='-')[0]
            elif key == 'ip_proto':
                # converting int from Tacker to str for OSM
                value = str(value)

        else:  # just remained OSM, so far

            if key in ('source-ip-address', 'destination-ip-address'):
                value = ''.join([value, '/32'])
            elif key in ('source-port', 'destination-port'):
                value = ''.join([value, '-', value])
            elif key == 'ip-proto':
                # converting string from OSM to int for Tacker
                value = int(value)

        key = policy_mapping[output_platform][index]

        return {key: value}

    def configure_multi_sfc_segments(self, sfc_segments):
        """Configures all multi-sfc segment tunnels and classifiers according to the configuration of the
        first classifier

        It configures all classifiers and tunnel vnfs in order to steer the traffic of an SFC through all segments

        :param sfc_segments: must contain a list with domains/nfvos and their respective sfc templates
        :return: sfc_segments with configured classifiers

        Raises
        ------
            MultiSFCException

        ReRaises
        ------
            NFVOAgentsException, DatabaseException
        """
        tunnel = None
        input_platform = None
        input_policies = None

        for segment in sfc_segments:
            domain_id = segment['domain_id']
            nfvo_id = segment['nfvo_id']
            platform = self._domain_catalog[domain_id][nfvo_id]['platform']

            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            if input_platform is None:  # it means that the segment is the first one
                input_platform = platform
                tunnel = self._domain_catalog[domain_id][nfvo_id]['tunnel']
                input_policies = nfvo_agent.get_policies(segment['sfc_template'])

            if self._domain_catalog[domain_id][nfvo_id]['tunnel'] != tunnel or tunnel is None:
                raise MultiSFCException("Configuration of segment tunnels mismatch!")

            tunnel_vnfp = database.list_catalog(platform=platform, tunnel=tunnel)
            if not tunnel_vnfp:
                raise MultiSFCException(
                    "No VNF Package found to configure %s tunnel! See domain configuration" % tunnel)

            vnfp_dir = tunnel_vnfp[0]['dir_id']
            vnfd_name = tunnel_vnfp[0]['vnfd_name']

            # if it is not the first segment, then add the tunnel vnf at the beginning of the segment
            if sfc_segments.index(segment) > 0:
                # Configuring acl policies based on the first segment classifier
                segment_policies = []
                for policy in input_policies:
                    policies = {}
                    for k, v in policy.items():
                        parsed_criteria = self.parse_segment_classifier_policy({k: v}, input_platform, platform)
                        if parsed_criteria is not None:
                            policies.update(parsed_criteria)
                    segment_policies.append(policies)

                segment['sfc_template'] = nfvo_agent.configure_policies(segment['sfc_template'], segment_policies)

                # Configuring the segment input VNF (tunnel)
                if platform == TACKER_NFVO:
                    # In case of Tacker, the VNF needs to be instantiated previously to be added on the classifier
                    vnf_name = str(vnfd_name).replace('vnfd', 'vnf')

                    vnfp_dir = '/'.join(['repository', vnfp_dir])
                    response = nfvo_agent.create_vnf(vnfp_dir, vnfd_name, vnf_name)
                    src_id = response['vnf_id']

                    database.insert_vnf_instance(tunnel_vnfp[0]['_id'], domain_id, nfvo_id,
                                                 response['vnfd_id'], response['vnf_id'])

                    segment['incoming_vnf'] = response['vnf_id']

                else:
                    src_id = tunnel_vnfp[0]['_id']

                segment['sfc_template'] = nfvo_agent.configure_traffic_src_policy(
                    segment['sfc_template'], INTERNAL, src_id, None, database)

            # if it is not the last segment, then add the tunnel vnf at the end of the segment
            if sfc_segments.index(segment) < len(sfc_segments) - 1:

                segment['sfc_template'] = nfvo_agent.compose_sfp(segment['sfc_template'], vnfd_name,
                                                                 vnfp_dir, database, None)

        return sfc_segments

    def _create_sfc_segment(self, segment, sfc_name, sfc_uuid, queue):
        """Implements a thread which instantiates a given Multi-SFC segment

        Note: All raised exceptions are put into the queue. The caller should read the queue
              and deal with the exceptions

        Raises
        ------
            MultiSFCException

        ReRaises
        ------
             NFVOAgentsException, DatabaseException, VIMAgentsException
        """
        try:
            domain_id = segment['domain_id']
            nfvo_id = segment['nfvo_id']
            segment_name = segment['segment_name']

            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            sfc = nfvo_agent.create_sfc(segment['sfc_template'], database, sfc_uuid, segment_name,
                                        self.create_vnf, self.destroy_vnf)

            # in case of tacker platform, on destroying the SFC segment the tunnel VNF must also be destroyed
            if 'incoming_vnf' in segment:
                sfc['vnf_instances'].insert(0, segment['incoming_vnf'])

            policies = nfvo_agent.get_policies(segment['sfc_template'])

            database.insert_sfc_instance(sfc_name, sfc_uuid, sfc['vnf_instances'], sfc['nsd_id'],
                                         sfc['ns_id'], segment_name, domain_id, nfvo_id, policies)

            # Configuring traffic policy rules (firewall) for each SFC segment
            vim_agent = nfvo_agent.get_vim_agent_instance()
            input_rules = nfvo_agent.get_sfc_input_security_policy_data(segment['sfc_template'])
            for rule in input_rules:
                try:
                    vim_agent.configure_security_policies(rule.get('proto'), rule.get('min_port'), rule.get('max_port'))
                except VIMAgentsException as e:
                    logger.error('Unable to configure security policies. Executing rollback actions...')
                    response = self.destroy_sfc(sfc_uuid)
                    if response['status'] != OK:
                        msg = ''.join([e.reason, response['reason']])
                        raise MultiSFCException(msg)

        except Exception:  # catching all exceptions
            # python does not propagate exceptions to the caller thread, so we need to put them into a queue
            queue.put(sys.exc_info())  # all exceptions are meant to be dealt by the caller
            return

        logger.info("Segment %s instantiated successfully!", segment_name)

    def create_sfc(self, sfc_data):
        """Sends and instantiates all segments of a Multi-SFC

        If an error occurs it also calls rollback actions

        :param sfc_data:
            input parameters are:

            - sfc_uuid: the unique identifier of the composed SFC to be started

        :return: OK if all succeed, or ERROR and its reason
        """
        try:
            sfc_segments = self.cache.get(sfc_data['sfc_uuid'])
            if not sfc_segments:
                return {'status': ERROR, 'reason': 'SFC UUID not found!'}

        except KeyError:
            return {'status': ERROR, 'reason': 'SFC UUID must be informed!'}

        sfc_name = sfc_data.get('sfc_name')
        if sfc_name:
            sfc_name = sfc_name.replace(' ', '')
        else:
            sfc_name = unique_id()

        try:
            if len(sfc_segments) > 1:
                sfc_segments = self.configure_multi_sfc_segments(sfc_segments)

            # instantiating all segments using threads, I/O bound, no GLI problem
            workers = []
            queue = Queue()  # queue to get return values from threads
            seg_num = 1
            for segment in sfc_segments:
                segment['segment_name'] = ''.join([sfc_name, '-seg', str(seg_num)])
                seg_num += 1

                t = Thread(target=self._create_sfc_segment, args=(segment, sfc_name, sfc_data['sfc_uuid'], queue))
                t.start()
                workers.append(t)

            for w in workers:  # waiting all threads to finish
                w.join()

            if not queue.empty():  # if queue has items, then at least an exception has been thrown
                logger.debug('Returned data from threads: %s', list(queue.queue))
                exc_info = queue.get()
                raise exc_info[1]  # the exception object is the second element of the tuple

            if len(sfc_segments) > 1:
                self.configure_tunnels(sfc_data['sfc_uuid'], sfc_segments)

        except (NFVOAgentsException, DatabaseException, VIMAgentsException) as ex:
            return {'status': ex.status, 'reason': ex.reason}
        except MultiSFCException as e:
            return {'status': ERROR, 'reason': str(e)}

        logger.info("Multi-SFC %s instantiated successfully!", sfc_name)

        self.cache.delete(sfc_data['sfc_uuid'])

        return {'status': OK}

    def _destroy_sfc_segment(self, segment, num_segments, queue):
        """Implements a thread which destroys a given Multi-SFC segment

        Note: All raised exceptions are put into the queue. The caller should read the queue
              and deal with the exceptions

        Raises
        ------
            MultiSFCException

        ReRaises
        ------
             NFVOAgentsException, DatabaseException
        """
        try:
            domain_id = segment['domain_id']
            nfvo_id = segment['nfvo_id']
            ns_id = segment['ns_id']
            routing = segment.get('routing')

            nfvo_agent = self._get_nfvo_agent_instance(domain_id, nfvo_id)

            nfvo_agent.destroy_sfc(ns_id, self.destroy_vnf)

            # in case tacker_agent, there is a need to remove the VNF of the multi-sfc tunnel
            if isinstance(nfvo_agent, TackerAgent) and num_segments > 1:
                vnf_id = segment['vnf_instances'][0]
                if database.list_vnf_instances(vnf_id=vnf_id):
                    response = self.destroy_vnf(vnf_id)
                    if response['status'] != OK:
                        msg = 'Unable to destroy VNF id %s: %s' % (vnf_id, response['reason'])
                        logger.error(msg)
                        raise NFVOAgentsException(ERROR, msg)

            # remove the route of the segment's virtual router in case it was configured (nat=False)
            if routing is not None:
                vim_agent = nfvo_agent.get_vim_agent_instance()
                try:
                    vim_agent.remove_route(routing['subnet_cidr'],
                                           routing['destination'],
                                           routing['next_hop'])
                except VIMAgentsException:
                    pass  # no action is needed, it is just logged on the server

            # remove SFC_Instance from database
            _id = segment['_id']
            database.remove_sfc_instance(_id)

        except Exception:  # catching all exceptions
            # python does not propagate exceptions to the caller thread, so we need to put them into a queue
            queue.put(sys.exc_info())  # all exceptions are meant to be dealt by the caller

    def destroy_sfc(self, multi_sfc_id):
        """Destroy all segments of a Multi-SFC

        :param multi_sfc_id: the multi-sfc unique identifier stored in database
        :return: OK if succeed, or ERROR and its reason if not
        """
        try:
            sfcs = database.list_sfc_instances(multi_sfc_id=multi_sfc_id)
            if not sfcs:
                raise MultiSFCException("Multi-SFC id '%s' cannot be destroyed. Not found in database." % multi_sfc_id)

            # destroying all segments using threads, I/O bound, no GLI problem
            workers = []
            queue = Queue()  # queue to get return values from threads
            for sfc in sfcs:
                t = Thread(target=self._destroy_sfc_segment, args=(sfc, len(sfcs), queue))
                t.start()
                workers.append(t)

            for w in workers:  # waiting all threads to finish
                w.join()

            if not queue.empty():  # if queue has items, then at least an exception has been thrown
                logger.debug('Returned data from threads: %s', list(queue.queue))
                exc_info = queue.get()
                raise exc_info[1]  # the exception object is the second element of the tuple

        except (NFVOAgentsException, DatabaseException) as e:
            return {'status': e.status, 'reason': e.reason}
        except MultiSFCException as ex:
            return {'status': ERROR, 'reason': str(ex)}

        return {'status': OK}

    def list_sfcs(self):
        """Retrieves all instantiated SFCs from each NFVO in all domains"""

        db_sfc_list = database.list_sfc_instances()
        multi_sfc_data = {}
        for sfc in db_sfc_list:
            segment = {
                sfc['ns_id']: {
                    'multi_sfc_id': sfc['multi_sfc_id'],
                    'sfc_name': sfc['sfc_name'],
                    'vnf_instances': sfc['vnf_instances'],
                    'classifier': sfc.get('classifier')
                }
            }
            multi_sfc_data.update(segment)

        data = []
        for domain in self._config_data['domains']:
            for nfvo in domain['nfvos']:
                nfvo_agent = nfvo['nfvo_agent']
                try:
                    sfcs = nfvo_agent.list_sfcs()
                    for sfc in sfcs:
                        try:
                            sfc['multi_sfc_id'] = multi_sfc_data.get(sfc['id']).get('multi_sfc_id')
                            sfc['sfc_name'] = multi_sfc_data.get(sfc['id']).get('sfc_name')
                            # replacing current vnf_chain
                            sfc['vnf_chain'] = multi_sfc_data.get(sfc['id']).get('vnf_instances')
                            sfc['policy'] = multi_sfc_data.get(sfc['id']).get('classifier')
                        except (AttributeError, KeyError):
                            sfc['multi_sfc_id'] = 'None'
                            sfc['sfc_name'] = 'None'
                            sfc['policy'] = 'None'

                        sfc['domain_name'] = domain['name']
                        sfc['nfvo_name'] = nfvo['name']
                    data.extend(sfcs)

                except NFVOAgentsException as e:
                    return {'status': e.status, 'reason': e.reason}

        return {'status': OK, 'sfcs': data}

    def configure_tunnels(self, sfc_uuid, sfc_segments):
        """Configures IP tunnels between all multi-sfc segments

        :param sfc_segments: all sfc segments used to create the multi-sfc
        :param sfc_uuid:
        :return:

        Raises
        ------
            MultiSFCException

        ReRaises
        ------
            DatabaseException, MultiSFCException, NFVOAgentsException, VIMAgentsException
        """

        logger.info("Configuring IP Tunnels for Multi-SFC %s", sfc_uuid)

        nfvo_agent = self._get_nfvo_agent_instance(sfc_segments[0]['domain_id'], sfc_segments[0]['nfvo_id'])

        # If there is src ip in the ACL, then use routing mode in tunnel, else configure nat mode
        # In case of using routing mode, a static route with the source ip must be configured on the
        # virtual router of the tunnel server side
        # Each pair of segments must have different subnet ranges to configure the IP Tunnel
        policies = nfvo_agent.get_policies(sfc_segments[0]['sfc_template'])
        source_address = None
        src_key = None
        if isinstance(nfvo_agent, TackerAgent):
            src_key = 'ip_src_prefix'
        elif isinstance(nfvo_agent, OSMAgent):
            src_key = 'src-ip-address'

        nat = True
        for policy in policies:
            source_address = policy.get(src_key)
            if source_address:
                nat = False  # there is no need to configure NAT if source address has been informed
                break

        # starts configuring from the second segment (first pair)
        for i in range(1, len(sfc_segments)):
            cur_segment = sfc_segments[i]
            prev_segment = sfc_segments[i - 1]

            tunnel_type = self._domain_catalog[cur_segment['domain_id']][cur_segment['nfvo_id']]['tunnel']

            # first VNF of current segment, it is also regarded as the tun server
            server_db_segment = database.list_sfc_instances(multi_sfc_id=sfc_uuid, domain_id=cur_segment['domain_id'],
                                                            nfvo_id=cur_segment['nfvo_id'])[0]

            tun_server_id = server_db_segment['vnf_instances'][0]  # getting the first VNF

            # last VNF of previous segment, it is regarded as the tun client
            tun_client_id = database.list_sfc_instances(multi_sfc_id=sfc_uuid, domain_id=prev_segment['domain_id'],
                                                        nfvo_id=prev_segment['nfvo_id'])[0]['vnf_instances'][-1]

            # getting TUN Server VNF
            server_nfvo_agent = self._get_nfvo_agent_instance(cur_segment['domain_id'], cur_segment['nfvo_id'])
            tun_server_vnf = server_nfvo_agent.show_vnf(tun_server_id)

            # getting TUN Client VNF
            client_nfvo_agent = self._get_nfvo_agent_instance(prev_segment['domain_id'], prev_segment['nfvo_id'])
            tun_client_vnf = client_nfvo_agent.show_vnf(tun_client_id)

            # getting TUN vim agent and opening TUN's EM configuration port
            server_vim_agent = server_nfvo_agent.get_vim_agent_instance()
            server_vim_agent.configure_security_policies(TUN_EM_PROTO, TUN_EM_PORT, TUN_EM_PORT)

            if tunnel_type == 'vxlan':

                # opening VXLAN port on TUN server
                server_vim_agent.configure_security_policies(VXLAN_PROTO, VXLAN_PORT, VXLAN_PORT)

                if i == 1:  # configure the previous segment only in the first loop
                    client_vim_agent = client_nfvo_agent.get_vim_agent_instance()
                    # opening port on VXLAN client
                    client_vim_agent.configure_security_policies(TUN_EM_PROTO, TUN_EM_PORT, TUN_EM_PORT)
                    client_vim_agent.configure_security_policies(VXLAN_PROTO, VXLAN_PORT, VXLAN_PORT)

                try:
                    vxlan_server = VXLANTunnel(tun_server_vnf['mgmt_address'], TUN_EM_PORT)
                    vxlan_client = VXLANTunnel(tun_client_vnf['mgmt_address'], TUN_EM_PORT)

                except TimeoutError as e:
                    raise MultiSFCException(e)

                tun_server_net = vxlan_server.get_networks()['response']
                tun_client_net = vxlan_client.get_networks()['response']

                # checking lan cidr, it still needs improvements
                if tun_server_net['lan_net'] == tun_client_net['lan_net']:
                    msg = "IP tunnel LAN must differ! Tunnel not configured between %s and %s" \
                          % (tun_client_net['wan_ip'], tun_server_net['wan_ip'])
                    logger.error(msg)
                    raise MultiSFCException(msg)

                vxlan_server.start(local_ip=tun_server_net['wan_ip'],
                                   remote_ip=tun_client_net['wan_ip'],
                                   server=True,
                                   route_net_host=tun_client_net['lan_net'],
                                   nat=nat)

                vxlan_client.start(local_ip=tun_client_net['wan_ip'],
                                   remote_ip=tun_server_net['wan_ip'],
                                   server=False,
                                   route_net_host=tun_server_net['lan_net'],
                                   nat=nat)

            elif tunnel_type == 'gre':
                # opening GRE proto on TUN server
                server_vim_agent.configure_security_policies(GRE_PROTO)

                if i == 1:  # configure the previous segment only in the first loop
                    client_vim_agent = client_nfvo_agent.get_vim_agent_instance()
                    # opening port on GRE client
                    client_vim_agent.configure_security_policies(TUN_EM_PROTO, TUN_EM_PORT, TUN_EM_PORT)
                    client_vim_agent.configure_security_policies(GRE_PROTO)

                try:
                    gre_server = GRETunnel(tun_server_vnf['mgmt_address'], TUN_EM_PORT)
                    gre_client = GRETunnel(tun_client_vnf['mgmt_address'], TUN_EM_PORT)

                except TimeoutError as e:
                    raise MultiSFCException(e)

                tun_server_net = gre_server.get_networks()['response']
                tun_client_net = gre_client.get_networks()['response']

                # checking lan cidr, it still needs improvements
                if tun_server_net['lan_net'] == tun_client_net['lan_net']:
                    msg = "IP tunnel LAN must differ! Tunnel not configured between %s and %s" \
                          % (tun_client_net['wan_ip'], tun_server_net['wan_ip'])
                    logger.error(msg)
                    raise MultiSFCException(msg)

                gre_server.start(local_ip=tun_server_net['wan_ip'],
                                 remote_ip=tun_client_net['wan_ip'],
                                 server=True,
                                 route_net_host=tun_client_net['lan_net'],
                                 nat=nat)

                gre_client.start(local_ip=tun_client_net['wan_ip'],
                                 remote_ip=tun_server_net['wan_ip'],
                                 server=False,
                                 route_net_host=tun_server_net['lan_net'],
                                 nat=nat)

            elif tunnel_type == 'ipsec':

                # opening IPSec ports on TUN server
                server_vim_agent.configure_security_policies(IPSEC_PROTO, IPSEC_PORT, IPSEC_PORT)
                server_vim_agent.configure_security_policies(IPSEC_PROTO, IPSEC_CHARON_PORT, IPSEC_CHARON_PORT)

                if i == 1:  # configure the previous segment only in the first loop
                    client_vim_agent = client_nfvo_agent.get_vim_agent_instance()
                    client_vim_agent.configure_security_policies(IPSEC_PROTO, IPSEC_PORT, IPSEC_PORT)
                    client_vim_agent.configure_security_policies(IPSEC_PROTO, IPSEC_CHARON_PORT, IPSEC_CHARON_PORT)

                try:
                    ipsec_server = IPSecTunnel(tun_server_vnf['mgmt_address'], TUN_EM_PORT)
                    ipsec_client = IPSecTunnel(tun_client_vnf['mgmt_address'], TUN_EM_PORT)

                except TimeoutError as e:
                    raise MultiSFCException(e)

                tun_server_net = ipsec_server.get_networks()['response']
                tun_client_net = ipsec_client.get_networks()['response']

                # checking lan cidr, it must be improved
                if tun_server_net['lan_net'] == tun_client_net['lan_net']:
                    msg = "IP tunnel LAN must differ! Tunnel not configured between %s and %s" \
                          % (tun_client_net['wan_ip'], tun_server_net['wan_ip'])
                    logger.error(msg)
                    raise MultiSFCException(msg)

                ipsec_server.start(local_ip=tun_server_net['wan_ip'],
                                   remote_ip=tun_client_net['wan_ip'],
                                   local_lan=tun_server_net['lan_net'],
                                   remote_lan=tun_client_net['lan_net'],
                                   nat=nat)

                ipsec_client.start(local_ip=tun_client_net['wan_ip'],
                                   remote_ip=tun_server_net['wan_ip'],
                                   local_lan=tun_client_net['lan_net'],
                                   remote_lan=tun_server_net['lan_net'],
                                   nat=nat)

            else:
                raise MultiSFCException("Tunnel type '%s' not implemented!" % tunnel_type)

            # configuring router to steer traffic back to the tunnel
            if not nat:
                if '/' not in source_address:
                    source_address = ''.join([source_address, '/32'])

                server_vim_agent.configure_route(tun_server_net['lan_net'],
                                                 source_address,
                                                 tun_server_net['lan_ip'])
                route = {
                    'subnet_cidr': tun_server_net['lan_net'],
                    'destination': source_address,
                    'next_hop': tun_server_net['lan_ip']
                }
                database.update_sfc_instance(server_db_segment['_id'], routing=route)
