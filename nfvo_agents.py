#!/usr/bin/env python
# -*- coding: utf-8 -*-

from interface import Interface


class NFVOAgents(Interface):

    def vnf_list(self):
        pass

    def vnf_create(self, vnfp_dir, vnfd_name, vnf_name):
        pass

    def vnf_delete(self, vnf_id):
        pass

    def sfc_list(self):
        pass

    def get_policies(self):
        pass

    def get_sfc_template(self):
        pass

    def compose_sfp(self, sfc_descriptor, vnfd_name, vnfp_dir, database, options_cp_out):
        pass

    def configure_traffic_src_policy(self, sfc_descriptor, origin, src_id, cp_out, database):
        pass

    def configure_policies(self, sfc_descriptor, acl):
        pass

    def create_sfc(self, sfc_descriptor, database, core, sfc_uuid, sfc_name):
        pass

    def destroy_sfc(self, sfc_id, core):
        pass

    def dump_sfc_descriptor(self, sfc_descriptor):
        pass
