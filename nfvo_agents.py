#!/usr/bin/env python
# -*- coding: utf-8 -*-

from interface import Interface


class NFVOAgents(Interface):

    def list_vnfs(self):
        pass

    def create_vnf(self, vnfp_dir, vnfd_name, vnf_name):
        pass

    def destroy_vnf(self, vnf_id):
        pass

    def show_vnf(self, vnf_id):
        pass

    def list_sfcs(self):
        pass

    def get_available_policies(self):
        pass

    def get_sfc_template(self):
        pass

    def get_policies(self, sfc_descriptor):
        pass

    def get_sfc_input_security_policy_data(self, sfc_descriptor):
        pass

    def compose_sfp(self, sfc_descriptor, vnfd_name, vnfp_dir, database, options_cp_out):
        pass

    def get_sfc_traffic_origin(self, core):
        pass

    def configure_traffic_src_policy(self, sfc_descriptor, origin, src_id, cp_out, database):
        pass

    def configure_policies(self, sfc_descriptor, policies):
        pass

    def create_sfc(self, sfc_descriptor, database, sfc_uuid, sfc_name, create_vnf_fn, destroy_vnf_fn):
        pass

    def destroy_sfc(self, sfc_id, destroy_vnf_fn):
        pass

    def dump_sfc_descriptor(self, sfc_descriptor):
        pass

    def get_vim_agent_instance(self):
        pass
