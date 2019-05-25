#!/usr/bin/env python

import configparser
import os
import requests
import logging

# Required imports for get_identity_info_keystone()
# from keystoneauth1.identity import v3
# from keystoneauth1 import session
# from keystoneclient.v3 import client

logger = logging.getLogger('tacker')


class IdentityManager:
    """
    Class responsible for identification and authentication of REST requests.
    """

    def __init__(self, host, username, password, tenant_name):
        CONFIG_FILE = 'tacker.conf'
        if not os.path.isfile(CONFIG_FILE):
            logger.critical("Missing tacker.conf file!")
            exit(1)

        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)

        self.tacker_url = "http://%s/" % host
        self.username = username
        self.password = password
        self.tenant_name = tenant_name
        self.fip_interfaces = config['sfc_fip_router_interface']

        self.header = {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        resp = self.get_identity_info()
        self.token = resp.headers.get('X-Subject-Token')
        self.identity_info = resp.json()

        # self.identity_info = self.get_identity_info_keystone()

    def get_fip_router_interfaces(self):
        """Return all FIP network configured interfaces in tacker.conf file

        :return: a dictionary containing all FIP network configured interfaces in tacker.conf file
        """

        return self.fip_interfaces

    def get_identity_info(self):
        """
        Request for tokens and endpoints info.
        """

        data = """{
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "name": "%s",
                            "password": "%s",
                            "domain": {
                                "id": "default"
                            }
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "id": "default"
                        },
                        "name": "%s"
                    }
                }
            }
        }""" % (self.username, self.password, self.tenant_name)

        url = self.tacker_url + 'identity/v3/auth/tokens'
        return requests.post(url, data=data, headers=self.header)

    def get_identity_info_keystone(self):
        """
        Authenticates using keystone client -- not using yet
        """

        pass

        # url = self.OPENSTACK_URL + 'identity/v3'
        # auth = v3.Password(auth_url=url,
        #                    username=self.USERNAME,
        #                    password=self.PASSWORD,
        #                    project_name=self.TENANT_NAME,
        #                    user_domain_name="default",
        #                    project_domain_name="default")
        # sess = session.Session(auth=auth)
        # keystone = client.Client(session=sess)
        #
        # # testing code
        # # tacker_service = keystone.services.list(name='tacker')[0]
        # # ep = keystone.endpoints.list(service=tacker_service, interface='public')
        # # tacker_ep = ep[0].url
        # # vnfs = sess.get(''.join([tacker_ep, 'v1.0/vnfs']))
        # # users = keystone.users.list()
        #
        # return keystone

    def get_token(self):
        """
        Return the token ID used to authenticate requests.
        """

        return self.token

    def get_endpoints(self):
        """
        Get endpoints public URLs of each OpenStack service.
        These endpoints are used for future requests.
        """

        endpoints = {}
        service_catalog = self.identity_info['token']['catalog']

        for service in service_catalog:
            name = service['name']
            for endpoint in service['endpoints']:
                if endpoint['interface'] == 'public':
                    url = endpoint['url']
                    endpoints[name] = url
                    break

        return endpoints


class Tacker:
    """
    Implementation of the Tacker Client REST API interface.
    """

    def __init__(self, token, tacker_endpoint):
        self.token = token
        self.header = {
            'Content-type' : 'application/json',
            'Accept'       : 'application/json',
            'X-Auth-Token' : token
        }
        self.tacker_endpoint = tacker_endpoint + 'v1.0'

    def vnfd_create(self, vnfd):
        """
        Create a VNF descriptor.
        Template should be a JSON text.
        """

        url = self.tacker_endpoint + '/vnfds'
        return requests.post(url, headers=self.header, data=vnfd)

    def vnfd_delete(self, vnfd_id):
        """
        Delete a given VNF descriptor.
        """

        url = self.tacker_endpoint + '/vnfds/' + vnfd_id
        return requests.delete(url, headers=self.header)

    def vnfd_list(self):
        """
        List all available VNF descriptors.
        """

        url = self.tacker_endpoint + '/vnfds'
        return requests.get(url, headers=self.header)

    def vnf_create(self, vnfd_id, vnf_name):
        """
        Create a instance of a VNF.
        """

        url = self.tacker_endpoint + '/vnfs'
        data = """{
            "vnf": {
                "attributes": {},
                "vim_id": "",
                "description": "",
                "vnfd_id": "%s",
                "name": "%s"
            }
        }""" % (vnfd_id, vnf_name)

        return requests.post(url, headers=self.header, data=data)

    def vnffgd_create(self, vnffgd):
        """Create a VNF Forwarding Graph Descriptor."""

        url = self.tacker_endpoint + '/vnffgds'
        return requests.post(url, headers=self.header, data=vnffgd)

    def vnffgd_list(self):
        """List all VNFFG Descriptors in Tacker"""

        url = self.tacker_endpoint + '/vnffgds'
        return requests.get(url, headers=self.header)

    def vnffgd_delete(self, vnffgd_id):
        """Delete a given VNFFGD"""

        url = self.tacker_endpoint + '/vnffgds/' + vnffgd_id
        return requests.delete(url, headers=self.header)

    def vnffg_create(self, vnffgd_id, vnf_mapping, vnffg_name):
        """Create a VNF Forwarding Graph."""

        url = self.tacker_endpoint + '/vnffgs'
        vnffg = """{
            "vnffg": {
                "vnffgd_id": "%s",
                "name": "%s",
                "vnf_mapping": %s,
                "symmetrical": false
            }
        }""" % (vnffgd_id, vnffg_name, vnf_mapping)

        logger.info(vnffg)

        return requests.post(url, headers=self.header, data=vnffg)

    def vnffg_list(self):
        """List all VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + '/vnffgs'
        return requests.get(url, headers=self.header)

    def vnffg_show(self, vnffg_id):
        """List a given VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + '/vnffgs/' + vnffg_id
        return requests.get(url, headers=self.header)

    def vnffg_delete(self, vnffg_id):
        """Delete a given VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + '/vnffgs/' + vnffg_id
        return requests.delete(url, headers=self.header)

    def vnf_delete(self, vnf_id):
        """
        Delete a given VNF.
        """

        url = self.tacker_endpoint + '/vnfs/' + vnf_id
        return requests.delete(url, headers=self.header)

    def vnf_update(self, vnf_id, update_file):
        """
        Update a given VNF.
        """

        url = self.tacker_endpoint + '/vnfs/' + vnf_id
        return requests.put(url, headers=self.header, data=update_file)

    def vnf_list(self):
        """
        List all VNFs.
        """

        url = self.tacker_endpoint + '/vnfs'
        return requests.get(url, headers=self.header)

    def vnf_show(self, vnf_id):
        """
        Show info about a given VNF.
        """

        url = self.tacker_endpoint + '/vnfs/' + vnf_id
        return requests.get(url, headers=self.header)

    def vnf_resources(self, vnf_id):
        """
        Show VDU and CP of a given VNF.
        """

        url = self.tacker_endpoint + '/vnfs/%s/resources' % vnf_id
        return requests.get(url, headers=self.header)

    def sfc_list(self):
        """List all SFCs."""

        url = self.tacker_endpoint + '/sfcs'
        return requests.get(url, headers=self.header)
