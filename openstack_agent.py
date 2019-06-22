#!/usr/bin/env python

import logging

from interface import implements
from neutronclient.common.exceptions import NeutronClientException

from exceptions import VIMAgentsException
from utils import ERROR
from vim_agents import VIMAgents

from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from keystoneclient.v3 import client as keystone_client
# from heatclient import client as heat_client
# from stackclient???

from urllib3.util import parse_url

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
        self.neutron = neutron_client.Client(session=self.session)
        self.keystone = keystone_client.Client(session=self.session)

        self.ip_address = parse_url(auth_url).host
        self.project_id = self._get_project_id(vim_project_name)

    def _get_project_id(self, project_name):
        projects = self.keystone.projects.list()
        for project in projects:
            if project.name == project_name:
                return project.id

    def _get_router_by_ip_address(self, subnet_cidr):
        """Retrieves a router by any of its subnet address

        :param subnet_cidr: a classless inter domain routing address
        :return: a neutron router object

        Raises
        ------
            VIMAgentsException
        """
        router_id = None

        subnets = self.neutron.list_subnets(cidr=subnet_cidr, tenant_id=self.project_id)
        try:
            subnet_id = subnets['subnets'][0]['id']
        except (IndexError, KeyError) as e:
            msg = "No subnet found with cidr address %s!" % subnet_cidr
            logger.error(' '.join([msg, "ERROR:", str(e)]))
            raise VIMAgentsException(ERROR, msg)

        ports = self.neutron.list_ports(device_owner="network:router_interface", tenant_id=self.project_id)
        for port in ports['ports']:
            for port_ip in port['fixed_ips']:
                if port_ip['subnet_id'] == subnet_id:
                    router_id = port['device_id']
                    break
            if router_id:
                break

        if router_id is None:
            msg = "No virtual router interface attached to subnet %s" % subnet_cidr
            logger.error(msg)
            raise VIMAgentsException(ERROR, msg)

        router = self.neutron.show_router(router_id)

        return router['router']

    def configure_route(self, router_subnet_cidr, destination, next_hop):
        """Adds a static route on a router which owns any interface with the router_cidr param

        :param router_subnet_cidr: any subnet cidr address to identify the virtual router
        :param destination: destination cidr
        :param next_hop: an ip address

        Raises
        ------
            VIMAgentsException
        ReRaises
        ------
            VIMAgentsException
        """

        router = self._get_router_by_ip_address(router_subnet_cidr)

        logger.info("Adding static route on VIM %s router=%s destination=%s, nexthop=%s",
                    self.ip_address, router['id'], destination, next_hop)

        routes = router['routes']
        static_route = {
            "destination": destination,
            "nexthop": next_hop
        }
        routes.append(static_route)

        static_routes = {
            "router": {
                "routes": routes
            }
        }

        try:
            result = self.neutron.update_router(router['id'], static_routes)

        except NeutronClientException as e:
            logger.error("Router %s: %s", router['id'], e.message)
            raise VIMAgentsException(ERROR, e.message)

        logger.debug("Static route added! %s", str(result))

    def remove_route(self, router_subnet_cidr, destination, next_hop):
        """Removes a static route on a router which owns any interface with the router_cidr param

        :param router_subnet_cidr: any subnet cidr address which identifies the router
        :param destination: destination cidr
        :param next_hop: an ip address

        Raises
        ------
            VIMAgentsException
        ReRaises
        ------
            VIMAgentsException
        """

        router = self._get_router_by_ip_address(router_subnet_cidr)

        logger.info("Removing static route on VIM %s router=%s destination=%s, nexthop=%s",
                    self.ip_address, router['id'], destination, next_hop)

        routes = router['routes']
        static_route = {
            "destination": destination,
            "nexthop": next_hop
        }
        try:
            routes.remove(static_route)
            static_routes = {
                "router": {
                    "routes": routes
                }
            }

            result = self.neutron.update_router(router['id'], static_routes)

            logger.debug("Static route removed! %s", str(result))

        except NeutronClientException as e:
            logger.error("Router %s: %s", router['id'], e.message)
            raise VIMAgentsException(ERROR, e.message)

        except ValueError:
            logger.error("Static route not found in router %s! destination=%s, next_hop=%s",
                         router['name'], destination, next_hop)

    def configure_network(self, name, cidr):
        # check if network name and cidr are configure in VIM, if not it configures the network
        raise NotImplementedError

    def configure_security_policies(self):
        groups = self.neutron.list_security_groups()
        rules = self.neutron.list_security_group_rules()

        print("")

    def list_vms(self):
        servers = self.nova.servers.list()
        vms = []

        for server in servers:
            vm = {
                'id': server.id,
                'name': server.name,
                'networks': dict(server.networks),
                'status': server.status
            }
            vms.append(vm)

        return vms

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
    openstack = OpenStackAgent('http://osm-vim.local/identity/v3', 'admin', 'devstack', 'admin')
    # vms = openstack.list_vms()
    # print(vms)
    # openstack.configure_networks()
    # openstack.configure_route("10.10.1.0/24", "179.24.1.0/24", "10.10.0.8")
    openstack.configure_security_policies()
    # openstack._get_router_by_ip_address('10.10.1.0/24')
