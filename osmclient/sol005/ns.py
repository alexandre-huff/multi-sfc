# Copyright 2018 Telefonica
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
OSM ns API handling
"""

from osmclient.common import utils
from osmclient.common.exceptions import ClientException
from osmclient.common.exceptions import NotFound
import yaml
import json


class Ns(object):

    def __init__(self, http=None, client=None):
        self._http = http
        self._client = client
        self._apiName = '/nslcm'
        self._apiVersion = '/v1'
        self._apiResource = '/ns_instances_content'
        self._apiBase = '{}{}{}'.format(self._apiName,
                                        self._apiVersion, self._apiResource)

    def list(self, filter=None):
        """Returns a list of NS
        """
        filter_string = ''
        if filter:
            filter_string = '?{}'.format(filter)
        resp = self._http.get_cmd('{}{}'.format(self._apiBase,filter_string))
        if resp:
            return resp
        return list()

    def get(self, name):
        """Returns an NS based on name or id
        """
        if utils.validate_uuid4(name):
            for ns in self.list():
                if name == ns['_id']:
                    return ns
        else:
            for ns in self.list():
                if name == ns['name']:
                    return ns
        raise NotFound("ns {} not found".format(name))

    def get_individual(self, name):
        ns_id = name
        if not utils.validate_uuid4(name):
            for ns in self.list():
                if name == ns['name']:
                    ns_id = ns['_id']
                    break
        resp = self._http.get_cmd('{}/{}'.format(self._apiBase, ns_id))
        #resp = self._http.get_cmd('{}/{}/nsd_content'.format(self._apiBase, ns_id))
        #print yaml.safe_dump(resp)
        if resp:
            return resp
        raise NotFound("ns {} not found".format(name))

    def delete(self, name, force=False):
        ns = self.get(name)
        querystring = ''
        if force:
            querystring = '?FORCE=True'
        http_code, resp = self._http.delete_cmd('{}/{}{}'.format(self._apiBase,
                                         ns['_id'], querystring))
        #print 'HTTP CODE: {}'.format(http_code)
        #print 'RESP: {}'.format(resp)
        if http_code == 202:
            print('Deletion in progress')
        elif http_code == 204:
            print('Deleted')
        else:
            msg = ""
            if resp:
                try:
                    msg = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to delete ns {} - {}".format(name, msg))

    def create(self, nsd_name, nsr_name, account, config=None,
               ssh_keys=None, description='default description',
               admin_status='ENABLED'):

        nsd = self._client.nsd.get(nsd_name)

        vim_account_id = {}

        def get_vim_account_id(vim_account):
            if vim_account_id.get(vim_account):
                return vim_account_id[vim_account]

            vim = self._client.vim.get(vim_account)
            if vim is None:
                raise NotFound("cannot find vim account '{}'".format(vim_account))
            vim_account_id[vim_account] = vim['_id']
            return vim['_id']

        ns = {}
        ns['nsdId'] = nsd['_id']
        ns['nsName'] = nsr_name
        ns['nsDescription'] = description
        ns['vimAccountId'] = get_vim_account_id(account)
        #ns['userdata'] = {}
        #ns['userdata']['key1']='value1'
        #ns['userdata']['key2']='value2'

        if ssh_keys is not None:
            # ssh_keys is comma separate list
            # ssh_keys_format = []
            # for key in ssh_keys.split(','):
            #     ssh_keys_format.append({'key-pair-ref': key})
            #
            # ns['ssh-authorized-key'] = ssh_keys_format
            ns['ssh-authorized-key'] = []
            for pubkeyfile in ssh_keys.split(','):
                with open(pubkeyfile, 'r') as f:
                    ns['ssh-authorized-key'].append(f.read())
        if config:
            ns_config = yaml.load(config)
            if "vim-network-name" in ns_config:
                ns_config["vld"] = ns_config.pop("vim-network-name")
            if "vld" in ns_config:
                for vld in ns_config["vld"]:
                    if vld.get("vim-network-name"):
                        if isinstance(vld["vim-network-name"], dict):
                            vim_network_name_dict = {}
                            for vim_account, vim_net in list(vld["vim-network-name"].items()):
                                vim_network_name_dict[get_vim_account_id(vim_account)] = vim_net
                            vld["vim-network-name"] = vim_network_name_dict
                ns["vld"] = ns_config["vld"]
            if "vnf" in ns_config:
                for vnf in ns_config["vnf"]:
                    if vnf.get("vim_account"):
                        vnf["vimAccountId"] = get_vim_account_id(vnf.pop("vim_account"))

                ns["vnf"] = ns_config["vnf"]

        #print yaml.safe_dump(ns)
        try:
            self._apiResource = '/ns_instances_content'
            self._apiBase = '{}{}{}'.format(self._apiName,
                                            self._apiVersion, self._apiResource)
            headers = self._client._headers
            headers['Content-Type'] = 'application/yaml'
            http_header = ['{}: {}'.format(key,val)
                          for (key,val) in list(headers.items())]
            self._http.set_http_header(http_header)
            http_code, resp = self._http.post_cmd(endpoint=self._apiBase,
                                       postfields_dict=ns)
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code in (200, 201, 202, 204):
                if resp:
                    resp = json.loads(resp)
                if not resp or 'id' not in resp:
                    raise ClientException('unexpected response from server - {} '.format(
                                      resp))
                return resp['id']
            else:
                msg = ""
                if resp:
                    try:
                        msg = json.loads(resp)
                    except ValueError:
                        msg = resp
                raise ClientException(msg)
        except ClientException as exc:
            message="failed to create ns: {} nsd: {}\nerror:\n{}".format(
                    nsr_name,
                    nsd_name,
                    exc.message)
            raise ClientException(message)

    def list_op(self, name, filter=None):
        """Returns the list of operations of a NS
        """
        ns = self.get(name)
        try:
            self._apiResource = '/ns_lcm_op_occs'
            self._apiBase = '{}{}{}'.format(self._apiName,
                                      self._apiVersion, self._apiResource)
            filter_string = ''
            if filter:
                filter_string = '&{}'.format(filter)
            http_code, resp = self._http.get2_cmd('{}?nsInstanceId={}'.format(
                                                       self._apiBase, ns['_id'],
                                                       filter_string) )
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code == 200:
                if resp:
                    resp = json.loads(resp)
                    return resp
                else:
                    raise ClientException('unexpected response from server')
            else:
                msg = ""
                if resp:
                    try:
                        resp = json.loads(resp)
                        msg = resp['detail']
                    except ValueError:
                        msg = resp
                raise ClientException(msg)
        except ClientException as exc:
            message="failed to get operation list of NS {}:\nerror:\n{}".format(
                    name,
                    exc.message)
            raise ClientException(message)

    def get_op(self, operationId):
        """Returns the status of an operation
        """
        try:
            self._apiResource = '/ns_lcm_op_occs'
            self._apiBase = '{}{}{}'.format(self._apiName,
                                      self._apiVersion, self._apiResource)
            http_code, resp = self._http.get2_cmd('{}/{}'.format(self._apiBase, operationId))
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code == 200:
                if resp:
                    resp = json.loads(resp)
                    return resp
                else:
                    raise ClientException('unexpected response from server')
            else:
                msg = ""
                if resp:
                    try:
                        resp = json.loads(resp)
                        msg = resp['detail']
                    except ValueError:
                        msg = resp
                raise ClientException(msg)
        except ClientException as exc:
            message="failed to get status of operation {}:\nerror:\n{}".format(
                    operationId,
                    exc.message)
            raise ClientException(message)

    def exec_op(self, name, op_name, op_data=None):
        """Executes an operation on a NS
        """
        ns = self.get(name)
        try:
            self._apiResource = '/ns_instances'
            self._apiBase = '{}{}{}'.format(self._apiName,
                                            self._apiVersion, self._apiResource)
            endpoint = '{}/{}/{}'.format(self._apiBase, ns['_id'], op_name)
            #print 'OP_NAME: {}'.format(op_name)
            #print 'OP_DATA: {}'.format(json.dumps(op_data))
            http_code, resp = self._http.post_cmd(endpoint=endpoint, postfields_dict=op_data)
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code in (200, 201, 202, 204):
                if resp:
                    resp = json.loads(resp)
                if not resp or 'id' not in resp:
                    raise ClientException('unexpected response from server - {}'.format(
                                      resp))
                print(resp['id'])
            else:
                msg = ""
                if resp:
                    try:
                        msg = json.loads(resp)
                    except ValueError:
                        msg = resp
                raise ClientException(msg)
        except ClientException as exc:
            message="failed to exec operation {}:\nerror:\n{}".format(
                    name,
                    exc.message)
            raise ClientException(message)

    def create_alarm(self, alarm):
        data = {}
        data["create_alarm_request"] = {}
        data["create_alarm_request"]["alarm_create_request"] = alarm
        try:
            http_code, resp = self._http.post_cmd(endpoint='/test/message/alarm_request',
                                       postfields_dict=data)
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code in (200, 201, 202, 204):
                #resp = json.loads(resp)
                print('Alarm created')
            else:
                msg = ""
                if resp:
                    try:
                        msg = json.loads(resp)
                    except ValueError:
                        msg = resp
                raise ClientException('error: code: {}, resp: {}'.format(
                                      http_code, msg))
        except ClientException as exc:
            message="failed to create alarm: alarm {}\n{}".format(
                    alarm,
                    exc.message)
            raise ClientException(message)

    def delete_alarm(self, name):
        data = {}
        data["delete_alarm_request"] = {}
        data["delete_alarm_request"]["alarm_delete_request"] = {}
        data["delete_alarm_request"]["alarm_delete_request"]["alarm_uuid"] = name
        try:
            http_code, resp = self._http.post_cmd(endpoint='/test/message/alarm_request',
                                       postfields_dict=data)
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code in (200, 201, 202, 204):
                #resp = json.loads(resp)
                print('Alarm deleted')
            else:
                msg = ""
                if resp:
                    try:
                        msg = json.loads(resp)
                    except ValueError:
                        msg = resp
                raise ClientException('error: code: {}, resp: {}'.format(
                                      http_code, msg))
        except ClientException as exc:
            message="failed to delete alarm: alarm {}\n{}".format(
                    name,
                    exc.message)
            raise ClientException(message)

    def export_metric(self, metric):
        data = {}
        data["read_metric_data_request"] = metric
        try:
            http_code, resp = self._http.post_cmd(endpoint='/test/message/metric_request',
                                       postfields_dict=data)
            #print 'HTTP CODE: {}'.format(http_code)
            #print 'RESP: {}'.format(resp)
            if http_code in (200, 201, 202, 204):
                #resp = json.loads(resp)
                return 'Metric exported'
            else:
                msg = ""
                if resp:
                    try:
                        msg = json.loads(resp)
                    except ValueError:
                        msg = resp
                raise ClientException('error: code: {}, resp: {}'.format(
                                      http_code, msg))
        except ClientException as exc:
            message="failed to export metric: metric {}\n{}".format(
                    metric,
                    exc.message)
            raise ClientException(message)

