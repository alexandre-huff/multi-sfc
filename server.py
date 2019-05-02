#!/usr/bin/env python

import string
import random
import logging
from multiprocessing.pool import Pool

from core import Core

from utils import *
from flask import Flask
from flask import request, jsonify
from tacker_agent import *
from shutil import rmtree
from database import DatabaseConnection
from copy import deepcopy
# from werkzeug.contrib.cache import MemcachedCache
from cachelib import MemcachedCache


# LOGGING
# basicConfig sets up all the logs from libraries
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(name)-12s  %(message)s")
logger = logging.getLogger('server')
# logger.setLevel(logging.INFO)
# # create console handler and set level to debug
# ch = logging.StreamHandler()
# # ch.setLevel(logging.DEBUG)
# # create formatter
# formatter = logging.Formatter('%(asctime)s - %(levelname)-8s - %(name)-20s : %(message)s')
# # add formatter to ch
# ch.setFormatter(formatter)
# # add ch to logger
# logger.addHandler(ch)
# # LOGGING conf up to here

app = Flask(__name__)

core = Core()


@app.route('/package', methods=['POST'])
def include_package():
    vnfd = request.json['vnfd']
    descriptor = json.loads(request.json['descriptor'])
    try:
        vnf_code = request.json['vnf']
    except KeyError:
        vnf_code = ''

    resp = core.include_package(vnfd, descriptor, vnf_code)

    return jsonify(resp)


@app.route('/catalog', methods=['GET'])
def list_catalog():
    return jsonify(core.list_catalog())


@app.route('/package/<pkg_id>', methods=['DELETE'])
def delete_package(pkg_id):
    return jsonify(core.delete_package(pkg_id))


@app.route('/vnfs', methods=['GET'])
def list_vnfs():
    return jsonify(core.list_vnfs())


@app.route('/vnfs/<vnf_pkg_id>', methods=['POST'])
def instantiate_vnf(vnf_pkg_id):
    return jsonify(core.instantiate_vnf(vnf_pkg_id))


@app.route('/vnfs/<vnf_id>', methods=['DELETE'])
def destroy_vnf(vnf_id):
    return jsonify(core.destroy_vnf(vnf_id))


# @app.route('/vnfs/package/<vnf_id>', methods=['GET'])
# def get_vnf_package(vnf_id):
#     return jsonify(core.get_vnf_package(vnf_id))
#


@app.route('/sfc/acl', methods=['GET'])
def list_acl():
    return jsonify(core.get_policies())


@app.route('/sfc/uuid', methods=['GET'])
def get_sfc_uuid():
    return jsonify(core.create_sfc_uuid())


@app.route('/vnfp/cps/<vnf_pkg_id>', methods=['GET'])
def list_vnf_pkg_cps(vnf_pkg_id):
    return jsonify(core.list_vnf_pkg_cps(vnf_pkg_id))


@app.route('/sfc/sfp/compose', methods=['POST'])
def compose_sfp():
    return jsonify(core.compose_sfp(request.json))


@app.route('/sfc/acl/origin', methods=['POST'])
def include_sfc_traffic_origin():
    return jsonify(core.include_classifier_policy(request.json))


@app.route('/sfc/acl', methods=['POST'])
def configure_policies():
    return jsonify(core.configure_policies(request.json))


@app.route('/sfc/start', methods=['POST'])
def create_sfc():
    return jsonify(core.create_sfc(request.json))


@app.route('/sfc/<sfc_id>', methods=['DELETE'])
def destroy_sfc(sfc_id):
    return jsonify(core.destroy_sfc(sfc_id))


@app.route('/sfc', methods=['GET'])
def list_sfcs():
    return jsonify(core.list_sfcs())


if __name__ == '__main__':
    # app.run(threaded=True)
    # app.run(threaded=False)
    app.run(processes=1, threaded=False, port=5050)
