#!/usr/bin/env python

import json
import requests
import os
from eve import Eve
from flask import request, jsonify
from subprocess import Popen, PIPE

app = Eve()

@app.route('/em/install', methods=['POST'])
def install():
    data = json.loads(request.form.get('json'))

    install_script = request.files['file']
    install_path = '/tmp/' + install_script.filename
    install_script.save(install_path)
    os.system('chmod +x %s' % install_path)

    if data['type'] == 'ipsec':
        args = [
            install_path,
            data['local_ip'],
            data['remote_ip'],
            data['local_lan'],
            data['remote_lan']
        ]
    elif data['type'] == 'vxlan':
        args = [
            install_path,
            data['action'],
            data['local_ip'],
            data['remote_ip'],
            data['iface'],
            data['id'],
            data['vxlan_local_ip'],
            data['vxlan_remote_ip'],
            data['route_net_host'],
            data['arp_proxy_remote_host'],
            data['arp_proxy_iface']
        ]

    install = Popen(' '.join(args), shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = install.communicate()

    if stderr:
        return jsonify({
            'status': 'ERROR',
            'response': stderr
        })

    return jsonify({
        'status': 'OK',
        'response': stdout
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
