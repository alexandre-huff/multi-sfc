#!/usr/bin/env python

import configparser
import os
from uuid import uuid4
import logging
import requests


logger = logging.getLogger('fake_tacker')


class IdentityManager:
    """
    Class responsible for identification and authentication of REST requests.
    """

    def __init__(self):
        self.USERNAME      = "admin"
        self.TENANT_NAME   = "admin"
        self.PASSWORD      = "devstack"

        self.header = {
            'Content-type' : 'application/json',
            'Accept'       : 'application/json'
        }

        self.identity_info = self.get_identity_info()

    def get_identity_info(self):
        """
        Request for tokens and endpoints info.
        """

        data = """{
            "auth": {
                "tenantName": "%s",
                "passwordCredentials": {
                    "username": "%s",
                    "password": "%s"
                }
            }
        }""" % (self.TENANT_NAME, self.USERNAME, self.PASSWORD)

        # url = self.OPENSTACK_URL + 'identity/v2.0/tokens'
        # return requests.post(url, data=data, headers=self.header).json()

        return {'token': ''}

    def get_token(self):
        """
        Return the token ID used to authenticate requests.
        """

        return str(uuid4())
        # return self.identity_info['access']['token']['id']

    def get_endpoints(self):
        """
        Get endpoints public URLs of each OpenStack service.
        These endpoints are used for future requests.
        """

        endpoints = {'tacker': ''}

        # endpoints = {}
        # service_catalog = self.identity_info['access']['serviceCatalog']
        #
        # for service in service_catalog:
        #     name = service['name']
        #     public_url = service['endpoints'][0]['publicURL']
        #     endpoints[name] = public_url

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
        self.tacker_endpoint = tacker_endpoint

    def vnfd_create(self, vnfd):
        """
        Create a VNF descriptor.
        Template should be a JSON text.
        """
        return MockResponse({'vnfd': {'id': str(uuid4())}}, 201)
        # url = self.tacker_endpoint + 'v1.0/vnfds'
        # return requests.post(url, headers=self.header, data=vnfd)

    def vnfd_delete(self, vnfd_id):
        """
        Delete a given VNF descriptor.
        """

        url = self.tacker_endpoint + 'v1.0/vnfds/' + vnfd_id
        return requests.delete(url, headers=self.header)

    def vnfd_list(self):
        """
        List all available VNF descriptors.
        """
        return MockResponse({'vnfds': []}, 200)
        # url = self.tacker_endpoint + 'v1.0/vnfds'
        # return requests.get(url, headers=self.header)

    def vnf_create(self, vnfd_id, vnf_name):
        """
        Create a instance of a VNF.
        """
        return MockResponse({'vnf': {'id': str(uuid4())}}, 201)
        # url = self.tacker_endpoint + 'v1.0/vnfs'
        # data = """{
        #     "vnf": {
        #         "attributes": {},
        #         "vim_id": "",
        #         "description": "",
        #         "vnfd_id": "%s",
        #         "name": "%s"
        #     }
        # }""" % (vnfd_id, vnf_name)
        #
        # return requests.post(url, headers=self.header, data=data)

    def vnffgd_create(self, vnffgd):
        """Create a VNF Forwarding Graph Descriptor."""

        return MockResponse({'vnffgd': {'id': str(uuid4())}}, 201)
        # url = self.tacker_endpoint + 'v1.0/vnffgds'
        # return requests.post(url, headers=self.header, data=vnffgd)

    def vnffgd_list(self):
        """List all VNFFG Descriptors in Tacker"""

        return MockResponse({'vnffgds': []}, 200)

    def vnffgd_delete(self, vnffgd_id):
        """Delete a given VNFFGD"""

        url = self.tacker_endpoint + 'v1.0/vnffgds/' + vnffgd_id
        return requests.delete(url, headers=self.header)

    def vnffg_create(self, vnffgd_id, vnf_mapping, vnffg_name):
        """Create a VNF Forwarding Graph."""

        return MockResponse({'vnffg': {'id': str(uuid4())}}, 201)
        # url = self.tacker_endpoint + 'v1.0/vnffgs'
        # vnffg = """{
        #     "vnffg": {
        #         "vnffgd_id": "%s",
        #         "name": "%s",
        #         "vnf_mapping": %s,
        #         "symmetrical": false
        #     }
        # }""" % (vnffgd_id, vnffg_name, vnf_mapping)
        #
        # print(vnffg)
        #
        # return requests.post(url, headers=self.header, data=vnffg)

    def vnffg_list(self):
        """List all VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + 'v1.0/vnffgs'
        return requests.get(url, headers=self.header)

    def vnffg_show(self, vnffg_id):
        """List a given VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + 'v1.0/vnffgs/' + vnffg_id
        return requests.get(url, headers=self.header)

    def vnffg_delete(self, vnffg_id):
        """Delete a given VNF Forwarding Graph in Tacker"""

        url = self.tacker_endpoint + 'v1.0/vnffgs/' + vnffg_id
        return requests.delete(url, headers=self.header)

    def vnf_delete(self, vnf_id):
        """
        Delete a given VNF.
        """

        url = self.tacker_endpoint + 'v1.0/vnfs/' + vnf_id
        return requests.delete(url, headers=self.header)

    def vnf_update(self, vnf_id, update_file):
        """
        Update a given VNF.
        """

        url = self.tacker_endpoint + 'v1.0/vnfs/' + vnf_id
        return requests.put(url, headers=self.header, data=update_file)

    def vnf_list(self):
        """
        List all VNFs.
        """
        return MockResponse({'vnfs': []}, 200)

    def vnf_show(self, vnf_id):
        """
        Show info about a given VNF.
        """

        # url = self.tacker_endpoint + 'v1.0/vnfs/' + vnf_id
        # return requests.get(url, headers=self.header)

        data = {
            "vnf": {
                "status": "ACTIVE",
                "description": "OpenWRT VNFD with parameterized VDU name",
                "vnfd_id": "a04b47d1-e8ad-4ef9-8341-eafec398ce02",
                "tenant_id": "6673e4d4e13340acb0b847f9ecde613b",
                "created_at": "2016-10-25 10:15:06",
                "updated_at": "2016-10-25 10:16:43",
                "instance_id": "178d3186-5b5f-483c-b2f5-75b484ec793e",
                "mgmt_url": "{\"VDU1\": \"192.168.120.3\"}",
                "vim_id": "f6bd6f24-7a0e-4111-8994-e108c5ee2ff2",
                "placement_attr": {
                    "region_name": "RegionOne",
                    "vim_name": "VIM0"
                },
                "error_reason": None,
                "attributes": {
                    "config": "vdus:\n  vdu1:\n    config: {firewall: 'package firewall\n\n        '}\n",
                    "monitoring_policy": "{\"vdus\": {\"VDU1\": {\"ping\": {\"actions\": {\"failure\": \"respawn\"}, \"name\": \"ping\", \"parameters\": {\"count\": 3, \"interval\": 10}, \"monitoring_params\": {\"count\": 3, \"interval\": 10}}}}}",
                    "param_values": "vdus:\n  vdu1:\n    param: {vdu-name: openwrt_vdu1}\n",
                    "heat_template": "heat_template_version: 2013-05-23\ndescription: 'OpenWRT with services\n\n  '\nparameters:\n  vdu-name:\n    type: string\n    description: Vdu name\n    default: test-vdu\nresources:\n  CP1:\n    type: OS::Neutron::Port\n    properties:\n      network: net_mgmt\n      port_security_enabled: false\n  CP2:\n    type: OS::Neutron::Port\n    properties:\n      network: net0\n      port_security_enabled: false\n  CP3:\n    type: OS::Neutron::Port\n    properties:\n      network: net1\n      port_security_enabled: false\n  VDU1:\n    type: OS::Nova::Server\n    properties:\n      config_drive: false\n      flavor: {get_resource: VDU1_flavor}\n      image: OpenWRT\n      name:\n        get_param: vdu-name\n      networks:\n      - port:\n          get_resource: CP1\n      - port:\n          get_resource: CP2\n      - port:\n          get_resource: CP3\n      user_data_format: SOFTWARE_CONFIG\n  VDU1_flavor:\n    properties: {disk: 1, ram: 512, vcpus: 1}\n    type: OS::Nova::Flavor\noutputs:\n  mgmt_ip-VDU1:\n    value:\n      get_attr: [CP1, fixed_ips, 0, ip_address]\n"
                },
                "id": "2b85ac49-e59e-4f22-89b8-42c3e27115ef",
                "name": "OpenWRT"
            }
        }
        return MockResponse(data, 200)

    def vnf_resources(self, vnf_id):
        """
        Show VDU and CP of a given VNF.
        """

        url = self.tacker_endpoint + 'v1.0/vnfs/%s/resources' % vnf_id
        return requests.get(url, headers=self.header)

    def sfc_list(self):
        """List all SFCs."""

        url = self.tacker_endpoint + 'v1.0/sfcs'
        return requests.get(url, headers=self.header)


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data
