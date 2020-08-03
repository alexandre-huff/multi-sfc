#!/usr/bin/env python

import logging
import json

from keystoneauth1.identity import v3
from keystoneauth1 import session
from tackerclient.common.exceptions import TackerClientException
from tackerclient.v1_0 import client as tacker_client
from keystoneclient.v3 import client as keystone_client

from exceptions import NFVOAgentsException
from utils import ERROR

logger = logging.getLogger('tacker')


class Tacker:
    """
    Implementation of the Tacker Client REST API interface.
    """

    def __init__(self, auth_url, username, password, project_name):
        """Instantiates a Tacker client

        Raises
        ------
            NFVOAgentsException
        """
        auth = v3.Password(auth_url=auth_url,
                           username=username,
                           password=password,
                           project_name=project_name,
                           user_domain_name="default",
                           project_domain_name="default")

        self.session = session.Session(auth=auth)
        self.keystone = keystone_client.Client(session=self.session)
        services = self.keystone.services.list(name='tacker')

        if len(services) == 1:
            endpoint = self.keystone.endpoints.list(service=services[0], interface='public')

            if len(endpoint) == 1:
                self.tacker = tacker_client.Client(session=self.session,
                                                   endpoint_url=endpoint[0].url)
            else:
                raise NFVOAgentsException(ERROR, "Tacker public endpoint not found")

        else:
            raise NFVOAgentsException(ERROR, "Tacker service not found")

    def _exception_handler(self, e):
        """Exception handler for the Tacker API

        This function is in charge of handling the exceptions caught from
        the Tacker class and generating the appropriate NFVOAgentsException
        """
        if isinstance(e, TackerClientException):
            raise NFVOAgentsException(e.status_code, e.message)
        elif isinstance(e, KeyError):
            logger.error('Unable to find key %s in Tacker response', e)
            raise NFVOAgentsException(ERROR, 'Key %s is missing' % e)
        else:
            logger.critical('unhandled exception: %s', e)
            raise NFVOAgentsException(ERROR, str(e))

    def vnfd_create(self, vnfd):
        """ Create a VNF descriptor

        Template should be a JSON text.
        """

        try:
            return self.tacker.create_vnfd(json.loads(vnfd))['vnfd']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnfd_delete(self, vnfd_id):
        """ Delete a given VNF descriptor

        Tacker client returns no content on success, thus no return to the caller is required

        Raises
        ------
            NFVOAgentsException on error
        """

        try:
            self.tacker.delete_vnfd(vnfd_id)

        except TackerClientException as e:
            self._exception_handler(e)

    def vnfd_list(self):
        """ List all available VNF descriptors """

        try:
            return self.tacker.list_vnfds()['vnfds']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnf_create(self, vnfd_id, vnf_name, vim_id):
        """ Create an instance of a VNF """

        data = """{
            "vnf": {
                "attributes": {},
                "vim_id": "%s",
                "description": "",
                "vnfd_id": "%s",
                "name": "%s"
            }
        }""" % (vim_id, vnfd_id, vnf_name)

        try:
            return self.tacker.create_vnf(json.loads(data))['vnf']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffgd_create(self, vnffgd):
        """Create a VNF Forwarding Graph Descriptor"""

        try:
            return self.tacker.create_vnffgd(vnffgd)['vnffgd']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffgd_list(self):
        """List all VNFFG Descriptors in Tacker"""

        try:
            return self.tacker.list_vnffgds()['vnffgds']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffgd_delete(self, vnffgd_id):
        """Delete a given VNFFGD"""

        try:
            self.tacker.delete_vnffgd(vnffgd_id)

        except TackerClientException as e:
            self._exception_handler(e)

    def vnffg_create(self, vnffgd_id, vnf_mapping, vnffg_name):
        """Create a VNF Forwarding Graph."""

        vnffg = """{
            "vnffg": {
                "vnffgd_id": "%s",
                "name": "%s",
                "vnf_mapping": %s,
                "symmetrical": false
            }
        }""" % (vnffgd_id, vnffg_name, vnf_mapping)

        logger.info(vnffg)

        try:
            return self.tacker.create_vnffg(json.loads(vnffg))['vnffg']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffg_list(self):
        """List all VNF Forwarding Graph in Tacker"""

        try:
            return self.tacker.list_vnffgs()['vnffgs']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffg_show(self, vnffg_id):
        """List a given VNF Forwarding Graph in Tacker"""

        try:
            return self.tacker.show_vnffg(vnffg_id)['vnffg']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnffg_delete(self, vnffg_id):
        """Delete a given VNF Forwarding Graph in Tacker"""

        try:
            self.tacker.delete_vnffg(vnffg_id)

        except TackerClientException as e:
            self._exception_handler(e)

    def vnf_delete(self, vnf_id):
        """ Delete a given VNF

        Tacker client returns no content on success, thus no return to the caller is required

        Raises
        ------
            NFVOAgentsException on error
        """

        try:
            self.tacker.delete_vnf(vnf_id)

        except TackerClientException as e:
            self._exception_handler(e)

    def vnf_list(self):
        """ List all VNFs """

        try:
            return self.tacker.list_vnfs()['vnfs']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnf_show(self, vnf_id):
        """ Show info about a given VNF """

        try:
            return self.tacker.show_vnf(vnf_id)['vnf']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vnf_resources(self, vnf_id):
        """ Show VDU and CP of a given VNF """

        try:
            return self.tacker.list_vnf_resources(vnf_id)['resources']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def sfc_list(self):
        """List all SFCs"""

        try:
            return self.tacker.list_sfcs()['sfcs']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vim_list(self):
        """List all VIMs"""

        try:
            return self.tacker.list_vims()['vims']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)

    def vim_show(self, vim_id):
        """Show a VIM by its id"""

        try:
            return self.tacker.show_vim(vim_id)['vim']

        except (TackerClientException, KeyError) as e:
            self._exception_handler(e)


if __name__ == "__main__":
    tacker = Tacker('http://200.17.212.238:35357/v3',
                    'admin',
                    'AIbxwOQKLyNhBBfJeqE9mSIE63PLrVgjJjbU3y35',
                    'admin')

    tacker.vim_show('')
