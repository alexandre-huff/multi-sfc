#!/usr/bin/env python
# -*- coding: utf-8 -*-

import uuid
import time
import socket
from contextlib import closing

# REST API status codes
status = {
    200: 'OK.',
    201: 'Created.',
    204: 'No Content.',
    400: 'Bad Request.',
    401: 'Unauthorized.',
    404: 'Not Found.',
    409: 'Conflict.',
    500: 'Internal Server Error.'
}

# common used status
OK      = 'OK'
ERROR   = 'ERROR'
TIMEOUT = 'TIMEOUT'
ACTIVE  = 'ACTIVE'
OPTIONS = 'OPTIONS'

# Generic execution domain/platform for VNFs
ANY = 'ANY'

# SFC network source traffic
INTERNAL = '1'
EXTERNAL = '2'

# VNF types
CLICK_VNF   = 'click'
GENERAL_VNF = 'general'

# NFV Platforms to orchestrate VNFs
TACKER_NFVO = 'tacker'
OSM_NFVO    = 'osm'

IPSEC_PROTO = 17
IPSEC_PORT = 500
IPSEC_CHARON_PORT = 4500

VXLAN_PROTO = 17
VXLAN_PORT = 4789

TUN_EM_PROTO = 6
TUN_EM_PORT = 8000

protocols = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp'
}


# Returns an unique ID
def unique_id():
    return str(uuid.uuid4())


tunnel_config_scripts = {
    'vxlan': 'em/vxlan.sh',
    'ipsec': 'em/ipsec.sh'
}


def socket_polling(ip_address, port, sleep_time=15, wait_time=600):
    """

    :param ip_address:
    :param port:
    :param sleep_time:
    :param wait_time:
    :return:

    Raises
    ------
        OSError, TimeoutError
    """
    timeout = time.time() + wait_time
    # time.sleep(sleep_time)

    while timeout > time.time():
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(5)
            try:
                sock.connect((ip_address, port))
                return
            except ConnectionError:
                time.sleep(sleep_time)
                continue

    raise TimeoutError("Timeout")
