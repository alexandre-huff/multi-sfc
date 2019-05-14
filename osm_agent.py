#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from time import sleep

from nfvo_agents import NFVOAgents
from interface import implements
from utils import OK, OSM_NFVO, ERROR, TIMEOUT

from osmclient.sol005 import client as osm
from osmclient.common.exceptions import NotFound, ClientException


logger = logging.getLogger('osm_agent')


class OSMAgent(implements(NFVOAgents)):

    def __init__(self):
        self.client = osm.Client(host='osm-nfvo.local')

    @staticmethod
    def _get_vnf_nsd_template(self):
        return {}

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

    def ns_polling(self, ns_id):
        timeout = 300
        sleep_interval = 5

        while timeout > 0:
            ns = self.client.ns.get(ns_id)
            try:
                ns_status = ns['admin']['deployed']['RO']['nsr_status']
            except KeyError:
                ns_status = 'KEY_ERROR'

            if ns_status == 'ACTIVE':
                return OK, ns
            elif ns_status not in ('BUILD', 'KEY_ERROR'):
                return ns_status, 'Unexpected error.'

            sleep(sleep_interval)
            timeout -= sleep_interval

        return TIMEOUT, 'TIMEOUT'

    def vnf_create(self, vnfp_dir, vnfd_name, vnf_name, click_function=None):

        vnfd_path = '%s/vnfd.tar.gz' % vnfp_dir
        nsd_path = '%s/nsd.tar.gz' % vnfp_dir

        try:
            vnfd = self.client.vnfd.get(vnfd_name)
            vnfd_id = vnfd['_id']
            logger.info("VNFD previously created with id %s", vnfd_id)

        except NotFound:
            vnfd_id = self.client.vnfd.create(vnfd_path)
            logger.info("VNFD created with id %s", vnfd_id)

        try:
            nsd_id = self.client.nsd.create(nsd_path)

        except ClientException as e:
            return {'status': ERROR, 'reason': e.args[0]}

        logger.info("NSD created with id %s", nsd_id)

        # TODO Change static argument VIM1
        ns_id = self.client.ns.create(nsd_id, vnf_name, 'VIM1')

        status, resp = self.ns_polling(ns_id)
        if status != OK:
            return {'status': status, 'reason': resp}

        vnf_id = resp['constituent-vnfr-ref'][0]
        vnf = self.client.vnf.get(vnf_id)

        vnf_ip = vnf['ip-address']

        return {
            'status': OK,
            'vnfd_id': vnfd_id,
            'vnf_id': vnf_id,
            'vnf_ip': vnf_ip
        }

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
