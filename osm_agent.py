#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nfvo_agents import NFVOAgents
from interface import implements
from utils import OK, OSM_NFVO

from osmclient.sol005 import client as osm


class OSMAgent(implements(NFVOAgents)):

    def __init__(self):
        self.client = osm.Client(host='osm-nfvo.local')

    def vnf_list(self):

        vnf_list = self.client.vnf.list()

        vnfs = []
        for vnf in vnf_list:
            vnf_id = vnf['id']
            vdu0 = vnf['vdur'][0]

            # OSM does not show a VNF name, just VDU names
            vnf_name = vnf['id']

            mgmt_url = vnf['ip-address']
            instance_name = vdu0['name']
            vnfd_id = vnf['vnfd-id']
            vnf_status = vdu0['status']

            vnfs.append({'vnf_id': vnf_id, 'vnf_name': vnf_name, 'instance_name': instance_name,
                         'mgmt_url': mgmt_url, 'vnfd_id': vnfd_id, 'vnf_status': vnf_status, 'platform': OSM_NFVO})

        return OK, vnfs

    def vnf_create(self, vnfp_dir, vnfd_name, vnf_name, click_function=None):
        raise NotImplementedError

    def vnf_delete(self, vnf_id):
        raise NotImplementedError

    def sfc_list(self):

        ns_instances = self.client.ns.list()

        ns_list = []
        for ns in ns_instances:
            ns_id = ns['id']
            name = ns['name']
            # state = ns['operational-status']
            state = ns['admin']['deployed']['RO']['nsr_status']
            desc = ns['instantiate_params']['nsDescription']
            sfp = ns['constituent-vnfr-ref']

            ns_list.append({
                'id': ns_id,
                'name': name,
                'status': state,
                'description': desc,
                'vnf_chain': sfp,
                'platform': OSM_NFVO
            })

        return OK, ns_list
