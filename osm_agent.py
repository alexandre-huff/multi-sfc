#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nfvo_agents import NFVOAgents
from interface import implements
from utils import OK

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
                         'mgmt_url': mgmt_url, 'vnfd_id': vnfd_id, 'vnf_status': vnf_status})

        return OK, vnfs

    def vnf_create(self, vnfd_data, vnf_name, click_function=None):
        pass

    def vnf_delete(self, vnf_id):
        pass
