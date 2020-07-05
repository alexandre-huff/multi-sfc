#!/usr/bin/env python

import requests
import os
from flask import request, jsonify, Flask
from subprocess import Popen, PIPE


SCRIPT = '/opt/tunnel'
SERVER = '200.17.212.241:5050'

app = Flask(__name__)


def run_script(command):
    install_process = Popen(' '.join(command), shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    stdout, stderr = install_process.communicate()

    return stdout, stderr


def update_script(script_type):
    url = 'http://' + SERVER + '/tunnel/em/' + script_type
    response = requests.get(url, headers={'Content-Type': 'application/octet-stream'}, timeout=15)

    with open(SCRIPT, 'wb') as f:
        f.write(response.content)
    os.system('chmod +x %s' % SCRIPT)


@app.route('/em/config', methods=['POST'])
def install():
    data = request.json

    if not os.path.exists(SCRIPT):
        update_script(data['type'])

    if data['action'] == 'start':

        if data['type'] == 'ipsec':
            args = [
                SCRIPT,
                data['action'],
                data['local_ip'],
                data['remote_ip'],
                data['local_lan'],
                data['remote_lan'],
                data['nat']
            ]
        elif data['type'] == 'vxlan':
            args = [
                SCRIPT,
                data['action'],
                data['local_ip'],
                data['remote_ip'],
                data['vxlan_local_ip'],
                data['vxlan_remote_ip'],
                data['route_net_host'],
                data['nat']
            ]
        elif data['type'] == 'gre':
            args = [
                SCRIPT,
                data['action'],
                data['local_ip'],
                data['remote_ip'],
                data['gre_local_ip'],
                data['gre_remote_ip'],
                data['route_net_host'],
                data['nat']
            ]
        else:
            return jsonify({
                'status': 'ERROR',
                'response': 'Unknown "%s" tunnel type' % data['type']
            })

    else:
        return jsonify({
            'status': 'ERROR',
            'response': 'Unknown action: "%s"' % data['action']
        })

    stdout, stderr = run_script(args)

    if stderr:
        return jsonify({
            'status': 'ERROR',
            'response': str(stderr).replace('\n', '! ')
        })

    return jsonify({
        'status': 'OK',
        'response': stdout
    })


@app.route('/em/networks/<tunnel>', methods=['GET'])
def list_networks(tunnel):
    args = [
        SCRIPT,
        'networks'
    ]

    if not os.path.exists(SCRIPT):
        update_script(tunnel)

    stdout, stderr = run_script(args)

    if stderr:
        return jsonify({
            'status': 'ERROR',
            'response': str(stderr).replace('\n', '! ')
        })

    result = str(stdout).split('\n')

    networks = {}
    for item in result:
        data = item.split('=')
        networks.update({data[0]: data[1]})

    return jsonify({
        'status': 'OK',
        'response': networks
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
