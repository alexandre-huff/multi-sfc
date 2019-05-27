#!/usr/bin/env python

import logging
from flask import Flask
from flask import request, jsonify
from core import Core
from utils import TACKER_NFVO, OSM_NFVO, OK, ERROR

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


@app.route('/catalog', methods=['GET'])
def list_catalog():
    return jsonify(core.list_catalog())


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


@app.route('/sfc/acl/<platform>', methods=['GET'])
def list_acl(platform):
    return jsonify(core.get_policies(platform))


@app.route('/sfc/uuid', methods=['GET'])
def get_sfc_uuid():
    return jsonify(core.create_sfc_uuid())


# @app.route('/vnfp/cps/<vnf_pkg_id>', methods=['GET'])
# def list_vnf_pkg_cps(vnf_pkg_id):
#     return jsonify(core.list_vnf_pkg_cps(vnf_pkg_id))


@app.route('/sfc/sfp/compose', methods=['POST'])
def compose_sfp():
    return jsonify(core.compose_sfp(request.json))


@app.route('/sfc/acl/origin/<platform>', methods=['GET'])
def get_sfc_traffic_origin(platform):
    if platform == TACKER_NFVO:
        # fields defines which information should be shown in client applications
        fields = [
            {'id': 'ID'},
            {'name': 'Name'},
            {'instance': 'Instance Name'},
            {'address': 'Mgmt Address'},
            {'status': 'Status'},
            {'platform': 'Platform'}
        ]

        vnfs = core.list_vnfs()

        src_vnfs = []
        for vnf in vnfs['vnfs']:
            if vnf.get('platform') == TACKER_NFVO:
                src_vnf = {
                    'id': vnf.get('vnf_id'),
                    'name': vnf.get('vnf_name'),
                    'instance': vnf.get('instance_name'),
                    'address': vnf.get('mgmt_url'),
                    'status': vnf.get('vnf_status'),
                    'platform': TACKER_NFVO
                }
                src_vnfs.append(src_vnf)
        return jsonify({
            'status': OK,
            'fields': fields,
            'vnfs': src_vnfs
        })

    elif platform == OSM_NFVO:
        fields = [
            {'category': 'VNF Category'},
            {'description': 'Description'},
            {'platform': 'Platform'}
            # {'id': 'ID'}
        ]

        vnfps = core.list_catalog()

        src_vnfps = []
        for vnfp in vnfps['vnfs']:
            if vnfp.get('platform') == OSM_NFVO:
                src_vnfp = {
                    'id': vnfp.get('_id'),
                    'category': vnfp.get('category'),
                    'description': vnfp.get('description'),
                    'platform': OSM_NFVO
                }
                src_vnfps.append(src_vnfp)

        return jsonify({
            'status': OK,
            'fields': fields,
            'vnfs': src_vnfps
        })

    else:
        return jsonify({'status': ERROR, 'reason': 'Platform %s not supported' % platform})


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
