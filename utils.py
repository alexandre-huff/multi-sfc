''#!/usr/bin/env python
# -*- coding: utf-8 -*-

import uuid

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


# Returns an unique ID
def unique_id():
    return str(uuid.uuid4())
