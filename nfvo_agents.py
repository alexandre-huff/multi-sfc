#!/usr/bin/env python
# -*- coding: utf-8 -*-

from interface import Interface


class NFVOAgents(Interface):

    def vnf_list(self):
        pass

    def vnf_create(self, vnfd_data, vnf_name, click_function=None):
        pass

    def vnf_delete(self, vnf_id):
        pass
