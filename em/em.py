#!/usr/bin/env python

import json
# import requests
import os
# from eve import Eve
from flask import request, jsonify, Flask
from subprocess import Popen, PIPE

# app = Eve()
app = Flask(__name__)


@app.route('/em/config', methods=['POST'])
def install():
    data = json.loads(request.form.get('json'))

    install_script = request.files['file']
    install_path = './' + install_script.filename
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
            data['vxlan_local_ip'],
            data['vxlan_remote_ip'],
            data['route_net_host'],
            data['nat']
        ]
    else:
        return jsonify({
            'status': 'ERROR',
            'response': 'Unknown "%s" tunnel type' % data['type']
        })

    install_process = Popen(' '.join(args), shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    stdout, stderr = install_process.communicate()

    if stderr:
        return jsonify({
            'status': 'ERROR',
            'response': str(stderr).replace('\n', '! ')
        })

    return jsonify({
        'status': 'OK',
        'response': str(stdout).replace('\n', '! ')
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
