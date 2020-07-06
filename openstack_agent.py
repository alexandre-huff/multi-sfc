#!/usr/bin/env python

import logging

from interface import implements
from neutronclient.common.exceptions import NeutronClientException

from exceptions import VIMAgentsException
from utils import ERROR, protocols
from vim_agents import VIMAgents

from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from keystoneclient.v3 import client as keystone_client

# from urllib3.util import parse_url

logger = logging.getLogger('openstack_agent')


class OpenStackAgent(implements(VIMAgents)):
    """Implementation of the OpenStack Agent"""

    def __init__(self, auth_url, username, password, vim_project_name, vim_name):

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

        # self.ip_address = parse_url(auth_url).host
        self.project_id = self._get_project_id(vim_project_name)
        self.vim_name = vim_name

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

    def get_fip_router_interface(self, net_name):
        """Retrieves Floating IP router network port ID

        :param net_name:
        :return: the router network_port_src_id from the router which has an interface attached on network net_name

        Raises
        ------
            VIMAgentsException
        """
        nets = self.neutron.list_networks(tenant_id=self.project_id, name=net_name)
        try:
            net_id = nets['networks'][0]['id']
        except (IndexError, KeyError) as e:
            msg = "No network found with name %s!" % net_name
            logger.error(' '.join([msg, "ERROR:", str(e)]))
            raise VIMAgentsException(ERROR, msg)

        ports = self.neutron.list_ports(device_owner="network:router_interface",
                                        tenant_id=self.project_id,
                                        network_id=net_id)
        # What is the best way to find out the port id when there is more than one router
        # sharing the same network in a same project
        try:
            port_id = ports['ports'][0]['id']
        except (IndexError, KeyError) as e:
            msg = "No router port configured in network %s!" % net_name
            logger.error(' '.join([msg, "ERROR:", str(e)]))
            raise VIMAgentsException(ERROR, msg)

        return port_id

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
                    self.vim_name, router['id'], destination, next_hop)

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

        logger.info("Removing static route from VIM %s router=%s destination=%s, nexthop=%s",
                    self.vim_name, router['id'], destination, next_hop)

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

    def configure_security_policies(self, ip_proto, port_range_min=None, port_range_max=None):
        """Adds a security policy rule on the openstack to allow traffic incoming into VNFs and SFCs

        :param ip_proto: IP protocol number
        :param port_range_min:
        :param port_range_max:

        Raises
        ------
            VIMAgentsException
        """
        if ip_proto is None:
            msg = "IP Protocol must have a value!"
            logger.error(msg)
            raise VIMAgentsException(ERROR, msg)

        ip_proto = int(ip_proto)

        logger.info("Configuring security policy rule on VIM %s protocol=%s, port_range_min=%s, port_range_max=%s",
                    self.vim_name, protocols[ip_proto], port_range_min, port_range_max)

        if ip_proto not in protocols:
            msg = "Protocol number %s not supported to configure traffic policies on VIM %s" \
                  % (ip_proto, self.vim_name)
            logger.error(msg)
            raise VIMAgentsException(ERROR, msg)

        groups = self.neutron.list_security_groups(project_id=self.project_id, name='default')['security_groups']

        if not groups:
            msg = "Default security group not found for tenant '%s' on VIM '%s'" % (self.project_id, self.vim_name)
            logger.error(msg)
            raise VIMAgentsException(ERROR, msg)

        group_id = groups[0]['id']

        policy = {
            "security_group_rule": {
                "direction": "ingress",
                # "port_range_min": "80",
                "ethertype": "IPv4",
                # "port_range_max": "80",
                # "protocol": "tcp",
                "protocol": protocols[ip_proto],
                # "remote_ip_prefix": "0.0.0.0/0",
                "security_group_id": group_id
            }
        }

        if port_range_min is not None or port_range_max is not None:
            port_range_min = int(port_range_min) if port_range_min is not None else int(port_range_max)
            port_range_max = int(port_range_max) if port_range_max is not None else int(port_range_min)

            policy['security_group_rule']['port_range_min'] = port_range_min
            policy['security_group_rule']['port_range_max'] = port_range_max

        prev_rule = None
        for rule in groups[0]['security_group_rules']:
            if rule['direction'] == 'ingress' \
                    and rule['ethertype'] == 'IPv4' \
                    and rule['protocol'] == protocols[ip_proto] \
                    and rule['port_range_min'] == port_range_min \
                    and rule['port_range_max'] == port_range_max:
                prev_rule = rule
                break

        if prev_rule is None:

            try:
                result = self.neutron.create_security_group_rule(body=policy)

                logger.info("Port opened! VIM=%s, rule_id=%s protocol=%s, port_range_min=%s, port_range_max=%s",
                            self.vim_name, result['security_group_rule']['id'], protocols[ip_proto],
                            port_range_min, port_range_max)

            except NeutronClientException as e:
                logger.error("VIM %s: %s", self.vim_name, e.message)
                raise VIMAgentsException(ERROR, e.message)

        else:
            logger.debug("A security group rule was already added with id %s",
                         prev_rule['id'])  # prev_rule['security_group_rules'][0]['id'])

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
    openstack = OpenStackAgent('http://tacker-nfvo.local:35357/v3',
                               'admin',
                               'AIbxwOQKLyNhBBfJeqE9mSIE63PLrVgjJjbU3y35',
                               'admin'
                               'test')
    # vms = openstack.list_vms()
    # print(vms)
    # openstack.configure_networks()
    # openstack.configure_route("10.10.1.0/24", "179.24.1.0/24", "10.10.0.8")
    # openstack.configure_security_policies(6, 9090, 9090)
    # openstack._get_router_by_ip_address('10.10.1.0/24')
    openstack.get_fip_router_interface('net1')
