#!/usr/bin/env python

import logging
from flask import Flask, send_file
from flask import request, jsonify, make_response
from utils import tunnel_config_scripts

from core import Core

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


@app.route('/tunnel/em', methods=['GET'])
def get_tunnel_em():
    try:
        response = make_response(send_file('em/tunnel_em.py', mimetype='application/octet-stream'))

    except FileNotFoundError as e:
        logger.error(str(e))
        response = make_response("EM script not found to configure IP tunnel\n", 404)

    return response


@app.route('/tunnel/em/<script>', methods=['GET'])
def get_tunnel_script(script):
    try:
        response = make_response(send_file(tunnel_config_scripts[script], mimetype='application/octet-stream'))

    except FileNotFoundError as e:
        logger.error(str(e))
        response = make_response("Tunnel script not found to configure IP tunnel\n", 404)

    return response


@app.route('/catalog/vnfs', methods=['GET'])
def list_catalog():
    return jsonify(core.list_catalog())


@app.route('/catalog/vnfs/<domain_id>/<nfvo_id>', methods=['GET'])
def list_domain_nfvo_vnfs(domain_id, nfvo_id):
    return jsonify(core.list_domain_nfvo_vnfs(domain_id, nfvo_id))


@app.route('/catalog/domains', methods=['GET'])
def list_domains():
    return jsonify(core.get_domain_catalog())


@app.route('/package', methods=['POST'])
def include_package():
    return jsonify(core.include_package(request.json))


@app.route('/package/<pkg_id>', methods=['DELETE'])
def delete_package(pkg_id):
    return jsonify(core.delete_package(pkg_id))


@app.route('/vnfs', methods=['GET'])
def list_vnfs():
    return jsonify(core.list_vnfs())


@app.route('/vnfs', methods=['POST'])
def instantiate_vnf():
    return jsonify(core.create_vnf(request.json))


@app.route('/vnfs/<vnf_id>', methods=['DELETE'])
def destroy_vnf(vnf_id):
    return jsonify(core.destroy_vnf(vnf_id))


# @app.route('/vnfs/package/<vnf_id>', methods=['GET'])
# def get_vnf_package(vnf_id):
#     return jsonify(core.get_vnf_package(vnf_id))
#


@app.route('/sfc/uuid', methods=['GET'])
def get_sfc_uuid():
    return jsonify(core.create_sfc_uuid())


# @app.route('/vnfp/cps/<vnf_pkg_id>', methods=['GET'])
# def list_vnf_pkg_cps(vnf_pkg_id):
#     return jsonify(core.list_vnf_pkg_cps(vnf_pkg_id))


@app.route('/sfc/sfp/compose', methods=['POST'])
def compose_sfp():
    return jsonify(core.compose_sfp(request.json))


@app.route('/sfc/acl/origin/<sfc_uuid>', methods=['GET'])
def get_sfc_traffic_origin(sfc_uuid):
    return jsonify(core.get_sfc_traffic_origin(sfc_uuid))


@app.route('/sfc/acl/origin', methods=['POST'])
def include_sfc_traffic_origin():
    return jsonify(core.include_classifier_policy(request.json))


@app.route('/sfc/acl/<sfc_uuid>', methods=['GET'])
def list_acl(sfc_uuid):
    return jsonify(core.get_policies(sfc_uuid))


@app.route('/sfc/acl', methods=['POST'])
def configure_policies():
    return jsonify(core.configure_policies(request.json))


@app.route('/sfc/start', methods=['POST'])
def create_sfc():
    return jsonify(core.create_sfc(request.json))


@app.route('/sfc/<multi_sfc_id>', methods=['DELETE'])
def destroy_sfc(multi_sfc_id):
    return jsonify(core.destroy_sfc(multi_sfc_id))


@app.route('/sfc', methods=['GET'])
def list_sfcs():
    return jsonify(core.list_sfcs())


if __name__ == '__main__':
    # app.run(threaded=True)
    # app.run(threaded=False)
    # Threads are required in order to allow downloading EM scripts while polling cloud-init
    # configuration scripts on tunnel VNFs
    app.run(host='0.0.0.0', processes=1, threaded=True, port=5050)
