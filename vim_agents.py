#!/usr/bin/env python
# -*- coding: utf-8 -*-

from interface import Interface


class VIMAgents(Interface):

    def configure_network(self, name, cidr):
        pass

    def configure_route(self, router_subnet_cidr, destination, next_hop):
        pass

    def remove_route(self, router_subnet_cidr, destination, next_hop):
        pass

    def configure_security_policies(self):
        pass
