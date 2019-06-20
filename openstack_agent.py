#!/usr/bin/env python

import logging

from interface import implements
from vim_agents import VIMAgents

from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client
# from heatclient import client as heat_client
# from stackclient???


logger = logging.getLogger('openstack_agent')


class OpenStackAgent(implements(VIMAgents)):
    """Implementation of the OpenStack Agent"""

    def __init__(self, auth_url, username, password, vim_project_name):

        # auth_url = 'http://tacker-vim.local/identity/v3'
        auth = v3.Password(auth_url=auth_url,
                           username=username,
                           password=password,
                           project_name=vim_project_name,
                           user_domain_name="default",
                           project_domain_name="default")
        self.session = session.Session(auth=auth)
        self.nova = nova_client.Client('2', session=self.session)

    def configure_networks(self):
        # check if networks are different, and configure routes on each router if needed
        # TODO implement static route configuration in order allow multi-sfc traffic exchange with no masquerading
        pass

    def configure_security_policies(self):
        # TODO configure incoming traffic by opening ports on openstack
        pass

    def get_vm(self, vm_name, mgmt_ip):

        servers = self.nova.servers.list(search_opts={'name': vm_name, 'ip': mgmt_ip})
        vm = {}

        for server in servers:
            if server.name == vm_name:
                for net in server.networks:
                    if mgmt_ip in server.networks[net]:
                        vm['id'] = server.id
                        vm['name'] = server.name
                        vm['networks'] = dict(server.networks)
                        vm['status'] = server.status
                        break

        return vm


if __name__ == "__main__":
    openstack = OpenStackAgent()
    # openstack.get_vm(None, None)
