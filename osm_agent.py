#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import tarfile
import yaml
from time import sleep, time
from exceptions import NFVOAgentsException
from nfvo_agents import NFVOAgents
from interface import implements
from utils import OSM_NFVO, ERROR, TIMEOUT, EXTERNAL, INTERNAL, unique_id

from osmclient.sol005 import client as osm
from osmclient.common.exceptions import NotFound, ClientException


logger = logging.getLogger('osm_agent')


class OSMAgent(implements(NFVOAgents)):
    """Implementation of the OSM Agent."""

    def __init__(self):
        self.client = osm.Client(host='200.17.212.239')

    def _get_repository_nsd_content(self, dir_id):
        dir_name = '/'.join([os.getcwd(), 'repository', dir_id])

        tar = tarfile.open(dir_name + '/nsd.tar.gz', 'r:gz')
        tar_files = tar.getnames()
        file_names = [f for f in tar_files if 'nsd.yaml' in f]
        tar_nsd = tar.extractfile(tar.getmember(file_names[0]))

        nsd_yaml = yaml.full_load(tar_nsd)

        tar.close()

        return nsd_yaml

    def list_vnfs(self):
        """Retrieves a list of VNFs"""

        try:
            vnf_list = self.client.vnf.list()
        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))

        vnfs = []
        for vnf in vnf_list:
            vnf_id = vnf['id']
            vdu0 = vnf['vdur'][0]

            # OSM does not show a VNF name, just VDU names
            vnf_name = vnf['id']

            mgmt_url = vnf.get('ip-address')
            instance_name = vdu0.get('name')
            vnfd_id = vnf.get('vnfd-id')
            vnf_status = vdu0.get('status')

            vnfs.append({'vnf_id': vnf_id, 'vnf_name': vnf_name, 'instance_name': instance_name,
                         'mgmt_url': mgmt_url, 'vnfd_id': vnfd_id, 'vnf_status': vnf_status, 'platform': OSM_NFVO})

        return vnfs

    def ns_polling(self, ns_id):
        """Constantly checks the creation status of the NS.

        Wait until the NS status is set to ACTIVE on OSM.

        :param ns_id:
        :return: an NS instance

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            ClientException
        """
        timeout_seconds = 300
        sleep_interval = 5

        logger.info("Polling NS with id %s, please wait...", ns_id)

        timeout = time() + timeout_seconds
        while timeout > time():
            ns = self.client.ns.get(ns_id)
            try:
                ns_status = ns['admin']['deployed']['RO']['nsr_status']
            except KeyError:
                if ns['operational-status'] == 'failed':
                    raise NFVOAgentsException(ERROR, ns['detailed-status'])
                ns_status = 'KEY_ERROR'

            if ns_status == 'ACTIVE':
                return ns
            elif ns_status not in ('BUILD', 'KEY_ERROR'):
                raise NFVOAgentsException(str(ns_status), 'Unexpected error.')

            sleep(sleep_interval)

        raise NFVOAgentsException(TIMEOUT, 'Timeout of %ss on polling NS id %s' % (timeout_seconds, ns_id))

    def create_vnf(self, vnfp_dir, vnfd_name, vnf_name):
        """Creates a VNF and its related NS.

        :param vnfp_dir:
        :param vnfd_name:
        :param vnf_name:
        :return: VNFD id, VNF id, and VNF ip

        Raises
        ------
            NFVOAgentsException
        """

        vnfd_path = '%s/vnfd.tar.gz' % vnfp_dir
        nsd_path = '%s/nsd.tar.gz' % vnfp_dir

        try:
            vnfd = self.client.vnfd.get(vnfd_name)
            vnfd_id = vnfd['_id']
            logger.info("VNFD previously created with id %s", vnfd_id)

        except NotFound:
            try:
                vnfd_id = self.client.vnfd.create(vnfd_path)
                logger.info("VNFD created with id %s", vnfd_id)
            except ClientException as e:
                raise NFVOAgentsException(ERROR, str(e))

        try:
            nsd_id = self.client.nsd.create(nsd_path)

            logger.info("NSD created with id %s", nsd_id)

            # TODO Change static argument VIM1
            ns_id = self.client.ns.create(nsd_id, vnf_name, 'VIM1', description=' ')
            logger.info("NS created with id %s", ns_id)

            ns = self.ns_polling(ns_id)

            vnf_id = ns['constituent-vnfr-ref'][0]
            vnf = self.client.vnf.get(vnf_id)

        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))

        vnf_ip = vnf['ip-address']

        return {
            'vnfd_id': vnfd_id,
            'vnf_id': vnf_id,
            'vnf_ip': vnf_ip
        }

    def destroy_vnf(self, vnf_id):
        """Destroys a VNF and its related NS.

        This operation just is done if the NS has only one VNF (i.e. this VNF)

        :param vnf_id:

        Raises
        ------
            NFVOAgentsException
        """

        try:
            vnf = self.client.vnf.get(vnf_id)
            ns = self.client.ns.get(vnf['nsr-id-ref'])

            if len(ns['constituent-vnfr-ref']) > 1:
                raise NFVOAgentsException(ERROR, "A Network Service depends on this VNF.")

            vnfd_id = vnf['vnfd-id']
            ns_id = ns['id']
            nsd_id = ns['nsd']['_id']

            resp = self.client.ns.delete(ns_id)
            logger.info("NS Instance %s - %s", ns_id, resp)

            sleep(2)

            resp = self.client.nsd.delete(nsd_id)
            logger.info("NSD %s - %s", nsd_id, resp)

            resp = self.client.vnfd.delete(vnfd_id)
            logger.info("VNFD %s - %s", vnfd_id, resp)

        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))

    def list_sfcs(self):
        """Retrieves a list of NS"""
        try:
            ns_instances = self.client.ns.list()

        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))

        ns_list = []
        for ns in ns_instances:
            ns_id = ns['id']
            name = ns['name']
            if ns['operational-status'] != 'running':
                state = ns['operational-status'].upper()
            else:
                state = ns['admin']['deployed']['RO']['nsr_status']

            # desc = ns['instantiate_params']['nsDescription']
            sfp = ns['constituent-vnfr-ref']
            # removing the first VNF ​​because it generates the SFC's incoming traffic in OSM
            sfp.pop(0)

            # If the instantiated NS is just a VNF (not SFC), then constituent-vnfr-ref had just one element
            # Realize that an SFC NS has in OSM at least two VNFs in constituent-vnfr-ref
            # So, by removing the first VNF we can conclude that if sfp is empty, then this NS
            # is just a VNF, not an SFC.
            if sfp:
                policy = ns['nsd']['vnffgd'][0]['classifier'][0]['match-attributes'][0]
                policy.pop('id')

                ns_list.append({
                    'id': ns_id,
                    'name': name,
                    'status': state,
                    'policy': policy,
                    'vnf_chain': sfp,
                    'platform': OSM_NFVO
                })

        return ns_list

    def get_policies(self):
        """Returns the OSM classifier ACL"""

        return {
            'ip-proto': 'IP protocol number',
            'source-ip-address': 'IP source address prefix',
            'destination-ip-address': 'IP destination address prefix',
            'source-port': 'Source port number',
            'destination-port': 'Destination port number'
        }

    def get_sfc_template(self):
        template = """
            nsd:nsd-catalog:
                nsd:
                -   id:          network-service_nsd
                    name:        network-service_nsd
                    short-name:  network-service_nsd
                    description: Network Service Template
                    vendor: OSM
                    version: '1.0'
            
                    logo: osm_2x.png
                    
                    constituent-vnfd:
                        # The member-vnf-index needs to be unique, starting from 1
                        # vnfd-id-ref is the id of the VNFD
                        # Multiple constituent VNFDs can be specified
                    # -   member-vnf-index: 1
                    #     vnfd-id-ref: vxlan-server-public_vnfd
                    # -   member-vnf-index: 2
                    #     vnfd-id-ref: ubuntu-forwarder1_vnfd
                    # -   member-vnf-index: 3
                    #     vnfd-id-ref: ubuntu-forwarder2_vnfd
            
                    vld:
                        # Networks for the VNFs
                        # -   id: vld1
                        #     vim-network-name: net_mgmt
                            # mgmt-network: True
                            # name: vld1-name
                            # short-name: vld1-sname
                            # type: ELAN
                            # provider-network:
                            #     overlay-type: VLAN
                            #     segmentation_id: <update>
                            # ip-profile-ref: ipprofileA
                        #      vnfd-connection-point-ref:
                            # Specify the constituent VNFs
                            # member-vnf-index-ref - entry from constituent vnf
                            # vnfd-id-ref - VNFD id
                            # vnfd-connection-point-ref - connection point name in the VNFD
                            # -   member-vnf-index-ref: 1
                            #     vnfd-id-ref: vxlan-server-public_vnfd
                            #     vnfd-connection-point-ref: vnf-cp0
                            # -   member-vnf-index-ref: 2
                            #     vnfd-id-ref: ubuntu-forwarder1_vnfd
                            #     vnfd-connection-point-ref: vnf-cp0
                            # -   member-vnf-index-ref: 3
                            #     vnfd-id-ref: ubuntu-forwarder2_vnfd
                            #     vnfd-connection-point-ref: vnf-cp0
                        # -   id: vld2
                        #     vim-network-name: net1
                        #     vnfd-connection-point-ref:
                        #     -   member-vnf-index-ref: 1
                        #         vnfd-id-ref: vxlan-server-public_vnfd
                        #         vnfd-connection-point-ref: vnf-cp1
                        #     -   member-vnf-index-ref: 2
                        #         vnfd-id-ref: ubuntu-forwarder1_vnfd
                        #         vnfd-connection-point-ref: vnf-cp1
                        #     -   member-vnf-index-ref: 3
                        #         vnfd-id-ref: ubuntu-forwarder2_vnfd
                        #         vnfd-connection-point-ref: vnf-cp1
                        # -   id: vld3
                        #     vim-network-name: public
                        #     vnfd-connection-point-ref:
                        #     -   member-vnf-index-ref: 1
                        #         vnfd-id-ref: vxlan-server-public_vnfd
                        #         vnfd-connection-point-ref: vnf-cp2
            
                    vnffgd:
                        # VNF Forwarding Graph Descriptors
                        -   id: vnffg1
                            name: vnffg1
                            short-name: vnffg1-name
                            description: VNFFG1 Template
                            vendor: ufpr
                            version: '1.0'
                            rsp:
                            -   id: rsp1
                                name: rsp1-name
                                vnfd-connection-point-ref:
                                # -   member-vnf-index-ref: 2
                                    # starts from 0
                                    # order: 0
                                    # vnfd-id-ref: ubuntu-forwarder1_vnfd
                                    # vnfd-connection-point-ref: vnf-cp1
                                # -   member-vnf-index-ref: 3
                                #     order: 1
                                #     vnfd-id-ref: ubuntu-forwarder2_vnfd
                                #     vnfd-connection-point-ref: vnf-cp1
            
                            classifier:
                            -   id: class1
                                name: class1-name
                                rsp-id-ref: rsp1
                                member-vnf-index-ref: 1
                                vnfd-id-ref: vnf-name_vnfd
                                vnfd-connection-point-ref: vnf-cp1
                                match-attributes:
                                -   id: match1
                                    # ip-proto: 6 # TCP
                                    # source-ip-address: 10.10.0.3
                                    # destination-ip-address: 10.10.1.101
                                    # source-port: 0
                                    # destination-port: 8080
                    """
        template = yaml.safe_load(template)
        return template

    def add_constituent_vnf_and_virtual_link(self, sfc_descriptor, vnfd_name, vnf_nsd, input_vnf=False):
        """Adds VNF and its VL to the NSD

        :param sfc_descriptor:
        :param vnfd_name:
        :param vnf_nsd:
        :param input_vnf: use True if the VNF being added is used as traffic source by the classifier
        :return: the NSD being composed
        """

        # vnf_nsd = self._get_repository_nsd_content(vnfp_dir)
        # vnf_nsd = vnf_nsd['nsd:nsd-catalog']['nsd'][0]
        constituent_vnfd = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['constituent-vnfd']
        if not constituent_vnfd:
            constituent_vnfd = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['constituent-vnfd'] = []
            sfc_vld = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vld'] = []
            # sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0][
            #     'vnfd-connection-point-ref'] = []
        else:
            sfc_vld = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vld']
            # sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0]['vnfd-connection-point-ref']

        for vnfd in constituent_vnfd:
            if vnfd_name in vnfd.values():
                raise NFVOAgentsException(ERROR, "The selected VNF Package was already added in this SFC!")

        # Adding Constituent VNFD
        # the first member must be reserved for the VNF which generates the input SFC traffic
        vnf_id_ref = vnf_nsd['constituent-vnfd'][0]['vnfd-id-ref']
        if not input_vnf:
            member_vnf_index = len(constituent_vnfd) + 2
            constituent_vnfd.append({'member-vnf-index': member_vnf_index, 'vnfd-id-ref': vnf_id_ref})
        else:
            member_vnf_index = 1
            constituent_vnfd.insert(0, {'member-vnf-index': member_vnf_index, 'vnfd-id-ref': vnf_id_ref})

        # Adding VNF Virtual Links
        for nsd_vl in vnf_nsd.get('vld'):
            sfc_vls = [sfc_vl for sfc_vl in sfc_vld if sfc_vl['vim-network-name'] == nsd_vl['vim-network-name']]

            # NSD of a single VNF has just one CP in a VL
            cp_name = nsd_vl['vnfd-connection-point-ref'][0]['vnfd-connection-point-ref']

            vl_cp_ref = {
                'member-vnf-index-ref': member_vnf_index,
                'vnfd-id-ref': vnf_id_ref,
                'vnfd-connection-point-ref': cp_name
            }

            net_name = nsd_vl.get('vim-network-name')

            if not sfc_vls:
                vld_id = len(sfc_vld) + 1
                vl = {
                    'id': ''.join(['vld', str(vld_id)]),
                    'vim-network-name': net_name,
                    'vnfd-connection-point-ref': [vl_cp_ref]
                }
                sfc_vld.append(vl)

            else:
                for sfc_vl in sfc_vld:
                    if sfc_vl.get('vim-network-name') == net_name:
                        if not input_vnf:
                            sfc_vl.get('vnfd-connection-point-ref').append(vl_cp_ref)
                        else:
                            sfc_vl.get('vnfd-connection-point-ref').insert(0, vl_cp_ref)
                        break

        return sfc_descriptor

    def compose_sfp(self, sfc_descriptor, vnfd_name, vnfp_dir, database, options_cp_out):
        """Performs VNF Chaining in the NSD Template.

        This function stands for VNF Chaining and its requirements for CPs and VLs using the SFC Template.
        The following rules are taken into account:

        #. Chooses the CP according to the same network of the previous CP.
            If the VNF is the first one, then the first CP is chosen (disregarding the management interface).

        #. If no CP is chosen automatically.
            Then an NFVOAgentsException is raised stating that there aren't suitable CP for the given VNF Package

        :param sfc_descriptor: the NS descriptor being composed
        :param vnfd_name:
        :param vnfp_dir:
        :param database: not used by this function
        :param options_cp_out: not used by this function
        :return: the OSM SFC Descriptor (i.e. NSD) being composed

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            NFVOAgentsException
        """

        vnf_nsd = self._get_repository_nsd_content(vnfp_dir)
        vnf_nsd = vnf_nsd['nsd:nsd-catalog']['nsd'][0]
        vnf_id_ref = vnf_nsd['constituent-vnfd'][0]['vnfd-id-ref']

        sfc_descriptor = self.add_constituent_vnf_and_virtual_link(sfc_descriptor, vnfd_name, vnf_nsd)

        constituent_vnfd = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['constituent-vnfd']
        # the current vnfd, now is the last one which was just added
        # by the previous call to "add_constituent_vnf_and_virtual_link" function
        member_vnf_index = constituent_vnfd[-1].get('member-vnf-index')

        sfc_vld = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vld']

        sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0]['vnfd-connection-point-ref']
        if not sfc_sfp:
            sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0][
                'vnfd-connection-point-ref'] = []
        else:
            sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0]['vnfd-connection-point-ref']

        # Adding VNFs in RSP. Here the SFC composition happens auto-magically
        for nsd_vl in vnf_nsd.get('vld'):

            if not nsd_vl.get('mgmt-network'):

                # NSD of a single VNF has just one CP in a VL
                cp_name = nsd_vl['vnfd-connection-point-ref'][0]['vnfd-connection-point-ref']
                net_name = nsd_vl.get('vim-network-name')

                vnffgd_cp_ref = {
                    'member-vnf-index-ref': member_vnf_index,
                    'vnfd-id-ref': vnf_id_ref,
                    'vnfd-connection-point-ref': cp_name
                }

                if not sfc_sfp:
                    vnffgd_cp_ref['order'] = 0
                    sfc_sfp.append(vnffgd_cp_ref)
                else:
                    # Checks if the previous VNF network name is the same of the current VNF network name
                    # It is impossible create SFC Chains crossing different VIM's subnet
                    previous_vnfd_cp = sfc_sfp[-1]
                    previous_net = None
                    for sfc_vl in sfc_vld:
                        for cp_ref in sfc_vl['vnfd-connection-point-ref']:
                            if cp_ref.get('vnfd-id-ref') == previous_vnfd_cp.get('vnfd-id-ref'):
                                if cp_ref.get('vnfd-connection-point-ref') == \
                                        previous_vnfd_cp.get('vnfd-connection-point-ref'):
                                    previous_net = sfc_vl.get('vim-network-name')
                                    break
                        if previous_net:
                            break
                    if previous_net == net_name:
                        vnffgd_cp_ref['order'] = previous_vnfd_cp.get('order') + 1
                        sfc_sfp.append(vnffgd_cp_ref)

        # Checks whether the current VNF was added on the SFC composition
        if sfc_sfp[-1]['vnfd-id-ref'] != vnf_id_ref:
            raise NFVOAgentsException(ERROR, "There is no suitable CP for chaining with the previous VNF!")

        # logger.info("\n%s", yaml.dump(sfc_descriptor))

        return sfc_descriptor

    def configure_traffic_src_policy(self, sfc_descriptor, origin, src_id, cp_out, database):
        """Includes ACL criteria according to INTERNAL or EXTERNAL traffic source

        INTERNAL traffic is sourced from VNFs managed by NFVO, while EXTERNAL traffic is sourced from everything
        out from NFVO networks.
        This function includes specific requirements to select the source port for OSM NFVO.
        One important rule is applied:
            1. OSMs network_name from the origin VNF CP must be the same as the input CP of the first VNF in the chain.

        :param sfc_descriptor:
        :param origin: INTERNAL or EXTERNAL as in *utils module*
        :param src_id: the VNF Package ID of the VNF which generates de SFC incoming traffic
        :param cp_out:
        :param database:
        :return: the NSD being composed

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            DatabaseException
        """

        if origin != INTERNAL:
            raise NFVOAgentsException(ERROR, "OSM does not allow incoming traffic from external networks!")

        vnfp = database.list_catalog(vnf_pkg_id=src_id)
        vnfp_dir = vnfp[0].get('dir_id')

        vnf_nsd = self._get_repository_nsd_content(vnfp_dir)
        vnf_nsd = vnf_nsd['nsd:nsd-catalog']['nsd'][0]
        vnfd_nsd_name = vnf_nsd.get('constituent-vnfd')[0].get('vnfd-id-ref')

        sfc_descriptor = self.add_constituent_vnf_and_virtual_link(sfc_descriptor, vnfd_nsd_name, vnf_nsd, True)

        constituent_vnfd = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['constituent-vnfd']
        # the VNFs which generates the source traffic was just included as first one in NSD
        vnf_id_ref = constituent_vnfd[0].get('vnfd-id-ref')
        member_vnf_index = constituent_vnfd[0].get('member-vnf-index')

        sfc_vld = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vld']
        classifier = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['classifier'][0]

        sfc_sfp = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['rsp'][0]['vnfd-connection-point-ref']
        first_sfp_vnf = sfc_sfp[0]

        # getting the vim-network-name from the first VNF of the SFP (RSP)
        net_name = None
        for sfc_vl in sfc_vld:
            for sfc_cp_ref in sfc_vl.get('vnfd-connection-point-ref'):
                if first_sfp_vnf.get('vnfd-id-ref') in sfc_cp_ref.values() and \
                        first_sfp_vnf.get('vnfd-connection-point-ref') in sfc_cp_ref.values():
                    net_name = sfc_vl.get('vim-network-name')
                    break
            if net_name:
                break

        # getting the cp_name from the source traffic based on the vim-network-name from the first SFP (RSP) VNF
        vnf_cp_ref = None
        for nsd_vl in vnf_nsd.get('vld'):
            if nsd_vl.get('vim-network-name') == net_name:
                vnf_cp_ref = nsd_vl['vnfd-connection-point-ref'][0]['vnfd-connection-point-ref']
                break

        if not vnf_cp_ref:
            raise NFVOAgentsException(ERROR, "No suitable CP on this VNF!")

        classifier['member-vnf-index-ref'] = member_vnf_index
        classifier['vnfd-id-ref'] = vnf_id_ref
        classifier['vnfd-connection-point-ref'] = vnf_cp_ref

        return sfc_descriptor

    def configure_policies(self, sfc_descriptor, acl):
        """Configure ACL rules on the Tacker SFC classifier"""

        criteria = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]['vnffgd'][0]['classifier'][0]['match-attributes'][0]

        # TODO Needs to implement a criteria parser and validator as in tacker_agent
        criteria.update(acl)

        return sfc_descriptor

    def create_sfc(self, sfc_descriptor, database, core, sfc_uuid, sfc_name):
        """Sends all VNFDs and the NSD to the OSM NFVO and instantiates the NS

        :param sfc_descriptor:
        :param database:
        :param core:
        :param sfc_uuid:
        :return: a dict containing:

            - a list of *vnf_instances* of the created SFC
            - the created *vnffgd_id*
            - the created *vnffg_id*

        Raises
        ------
            NFVOAgentsException

        ReRaises
        ------
            DatabaseException
        """
        desc_file = 'template/osm_nsd/nsd.yaml'
        nsd_file = 'template/%s_nsd.tar.gz' % sfc_uuid
        vnfp_template_dir = 'template/osm_nsd/'

        try:
            self.client.nsd.get(sfc_name)
            raise NFVOAgentsException(ERROR, "SFC name '%s' already exists" % sfc_name)
        except NotFound:
            pass

        try:
            self.client.ns.get(sfc_name)
            raise NFVOAgentsException(ERROR, "SFC name '%s' already exists" % sfc_name)
        except NotFound:
            pass

        nsd = sfc_descriptor['nsd:nsd-catalog']['nsd'][0]
        nsd['id'] = sfc_uuid
        nsd['name'] = sfc_name
        nsd['short-name'] = sfc_name

        yaml_file = open(desc_file, 'w')
        yaml_file.write(yaml.dump(sfc_descriptor))
        yaml_file.close()

        logger.info('SFC Template UUID: %s\n%s', sfc_uuid,
                    self.dump_sfc_descriptor(sfc_descriptor))

        constituent_vnfd = nsd.get('constituent-vnfd')

        for vnfd in constituent_vnfd:
            vnfd_name = vnfd.get('vnfd-id-ref')
            vnfp = database.list_catalog(vnfd_name=vnfd_name)

            vnfd_path = 'repository/%s/vnfd.tar.gz' % vnfp[0]['dir_id']

            try:
                vnfd = self.client.vnfd.get(vnfd_name)
                vnfd_id = vnfd['_id']
                logger.info("VNFD previously created with id %s", vnfd_id)

            except NotFound:
                try:
                    vnfd_id = self.client.vnfd.create(vnfd_path)
                    logger.info("VNFD created with id %s", vnfd_id)
                except ClientException as e:
                    raise NFVOAgentsException(ERROR, str(e))

        tar = tarfile.open(nsd_file, 'w:gz')
        tar.add(vnfp_template_dir, arcname='template_nsd', recursive=True)
        tar.close()

        try:
            nsd_id = self.client.nsd.create(nsd_file)
            logger.info("NSD created with id %s", nsd_id)

            ns_id = self.client.ns.create(nsd['name'], sfc_name, 'VIM1', description=' ')
            logger.info("NS created with id %s", ns_id)

            ns = self.ns_polling(ns_id)

        except NFVOAgentsException as e:
            logger.error("NS %s could not be created! %s", sfc_name, e.reason)
            logger.error("Running rollback actions...")
            self.destroy_sfc(sfc_name, core)
            raise NFVOAgentsException(e.status, e.reason)

        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))
        finally:
            os.remove(nsd_file)

        vnf_instances = ns['constituent-vnfr-ref']

        return {
            'vnf_instances': vnf_instances,
            'nsd_id': nsd_id,
            'ns_id': ns_id
        }

    def destroy_sfc(self, sfc_id, core):
        """ Destroys an NS and its related NSD and VNFDs

        :param sfc_id:
        :param core: no used by this agent
        """

        try:
            ns = self.client.ns.get(sfc_id)

            resp = self.client.ns.delete(sfc_id)
            logger.info("NS %s - %s", sfc_id, resp)

            sleep(2)

            resp = self.client.nsd.delete(ns['nsd']['_id'])
            logger.info("NSD %s - %s", ns['nsd']['_id'], resp)

        except ClientException as e:
            raise NFVOAgentsException(ERROR, str(e))

        constituent_vnfd = ns['nsd']['constituent-vnfd']
        for vnfd in constituent_vnfd:
            try:
                resp = self.client.vnfd.delete(vnfd['vnfd-id-ref'])
                logger.info("VNFD %s - %s", vnfd['vnfd-id-ref'], resp)
            except ClientException as e:
                logger.info("Trying to delete %s", str(e))

    def dump_sfc_descriptor(self, sfc_descriptor):
        return yaml.dump(sfc_descriptor)
