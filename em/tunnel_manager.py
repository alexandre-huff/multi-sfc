#!/usr/bin/env python

import requests
import json
import logging

import os
import sys
import inspect
from exceptions import MultiSFCException

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from utils import socket_polling, OK

headers = {'Content-Type': 'application/json'}

logger = logging.getLogger('tun_manager')


class VXLANTunnel:

    def __init__(self, ip_address, port=8000):
        """

        :param ip_address:
        :param port:

        Raises
        ------
            TimeoutError
        """
        self.base_url = ''.join(['http://', ip_address, ':', str(port), '/em'])

        logger.info("Polling VXLAN EM endpoint at %s:%s", ip_address, port)

        try:
            socket_polling(ip_address, port)

        except (OSError, TimeoutError) as err:
            raise TimeoutError("VXLAN management interface at %s:%s is closed. %s." % (ip_address, port, err))

    def get_networks(self):
        networks = requests.get(self.base_url + '/networks/vxlan', headers=headers, timeout=15)

        return networks.json()

    def start(self, local_ip, remote_ip, server, route_net_host, nat):
        """Starts one endpoint of a VXLAN Tunnel

        :param local_ip: wan ip
        :param remote_ip:
        :param server: True if server, False otherwise
        :param route_net_host: the route to be installed to route vxlan traffic to the remote host
        :param nat: True if use MASQUERADE, False otherwise
        :return:


        Raises
        ------
            MultiSFCException
        """
        data = {
            'type': 'vxlan',
            'action': 'start',
            'local_ip': local_ip,
            'remote_ip': remote_ip,
            'route_net_host': route_net_host,
            'nat': str(nat)
        }

        if server:
            data['vxlan_local_ip'] = '192.168.200.1/30'
            data['vxlan_remote_ip'] = '192.168.200.2'
        else:
            data['vxlan_local_ip'] = '192.168.200.2/30'
            data['vxlan_remote_ip'] = '192.168.200.1'

        # data['nat'] = 'True' if nat else 'False'

        result = requests.post(self.base_url + '/config', data=json.dumps(data), headers=headers, timeout=60)

        if result.status_code != 200:
            msg = result.content.decode('utf-8')
            logger.error(msg)
            raise MultiSFCException(msg)

        result = result.json()
        if result['status'] != OK:
            logger.error(result['response'])
            raise MultiSFCException(result['response'])

        return result

    def stop(self):
        """Stops one endpoint of a VXLAN Tunnel

        :return:

        Raises
        ------
            MultiSFCException
        """
        data = {
            'type': 'vxlan',
            'action': 'stop'
        }
        result = requests.post(self.base_url + '/config', data=json.dumps(data), headers=headers, timeout=15)

        if result.status_code != 200:
            msg = result.content.decode('utf-8')
            logger.error(msg)
            raise MultiSFCException(msg)

        result = result.json()
        if result['status'] != OK:
            logger.error(result['response'])
            raise MultiSFCException(result['response'])

        return result


class IPSecTunnel:
    def __init__(self, ip_address, port=8000):
        self.base_url = ''.join(['http://', ip_address, ':', str(port), '/em'])

        logger.info("Polling IPSec EM endpoint at %s:%s", ip_address, port)

        try:
            socket_polling(ip_address, port)

        except (OSError, TimeoutError) as err:
            raise TimeoutError("IPSec management interface at %s:%s is closed. %s." % (ip_address, port, err))

    def get_networks(self):
        networks = requests.get(self.base_url + '/networks/ipsec', headers=headers, timeout=15)

        return networks.json()

    def start(self, local_ip, remote_ip, local_lan, remote_lan, nat):
        """

        :param local_ip: wan ip
        :param remote_ip:
        :param local_lan: e.g. 10.10.0.0/24
        :param remote_lan: e.g. 10.10.1.0/24
        :param nat: True if use MASQUERADE, False otherwise
        :return:

        Raises
        ------
            MultiSFCException
        """
        data = {
            'type': 'ipsec',
            'action': 'start',
            'local_ip': local_ip,
            'remote_ip': remote_ip,
            'local_lan': local_lan,
            'remote_lan': remote_lan,
            'nat': str(nat)
        }

        result = requests.post(self.base_url + '/config', data=json.dumps(data), headers=headers, timeout=300)

        if result.status_code != 200:
            msg = result.content.decode('utf-8')
            logger.error(msg)
            raise MultiSFCException(msg)

        result = result.json()
        if result['status'] != OK:
            logger.error(result['response'])
            raise MultiSFCException(result['response'])

        return result


if __name__ == "__main__":

    try:
        ipsec = IPSecTunnel('192.168.240.23')
    except TimeoutError as e:
        print(str(e))
        sys.exit(0)

    resp = ipsec.get_networks()['response']
    print(resp)

    response = ipsec.start(resp['wan_ip'], '172.24.241.3', '10.10.0.0/24', '10.10.1.0/24', True)
    # response = vxlan.stop()
    print(response)
    # print(response.json())
