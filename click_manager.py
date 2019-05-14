#!/usr/bin/env python

import requests
import logging

logger = logging.getLogger('click_em')


class ElementManagement:
    """Implementation of the Click-on-OSv Element Management (EM)."""

    def __init__(self):
        self.header = {'Content-Type': 'application/json'}

    # Click on OSv URL
    def get_url(self, vnf_ip, task):
        return ''.join(['http://', vnf_ip, ':8000/click_plugin/', task])

    def is_ready(self, vnf_ip, vnf_id):
        import socket
        from contextlib import closing

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex((vnf_ip, 8000)) == 0:
                logger.info('VNF %s Socket %s:8000 is open' % (vnf_id, vnf_ip))
                return True
            else:
                logger.info('VNF %s Socket %s:8000 is not open' % (vnf_id, vnf_ip))
                return False

    def get_version(self, vnf_ip):
        """Return Click version."""

        url = self.get_url(vnf_ip, 'version')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def get_running(self, vnf_ip):
        """Return Click status."""

        url = self.get_url(vnf_ip, 'running')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def read_function(self, vnf_ip):
        """Return VNF function content."""

        url = self.get_url(vnf_ip, 'read_file')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def get_vnf_id(self, vnf_ip):
        """Return VNF identification."""

        url = self.get_url(vnf_ip, 'vnf_identification')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def get_log(self, vnf_ip):
        """Return Click log."""

        url = self.get_url(vnf_ip, 'log')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def get_metrics(self, vnf_ip):
        """Return usage metrics from Click."""

        url = self.get_url(vnf_ip, 'metrics')
        payload = {'op': 'GET'}
        return requests.get(url, data=payload, headers=self.header)

    def write_function(self, vnf_ip, function):
        """Write VNF function."""

        url = self.get_url(vnf_ip, 'write_file')
        payload = {'path': 'func.click', 'content': function}
        return requests.post(url, data=payload)

    def stop_function(self, vnf_ip):
        """Stop VNF function."""

        url = self.get_url(vnf_ip, 'stop')
        payload = {'op': 'POST'}
        return requests.post(url, data=payload, headers=self.header)

    def start_function(self, vnf_ip):
        """Start VNF function."""

        url = self.get_url(vnf_ip, 'start')
        payload = {'op': 'POST'}
        return requests.post(url, data=payload, headers=self.header)
