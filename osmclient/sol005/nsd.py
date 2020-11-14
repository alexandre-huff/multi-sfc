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
OSM nsd API handling
"""

from osmclient.common.exceptions import NotFound
from osmclient.common.exceptions import ClientException
from osmclient.common import utils
import json
import magic
#from os import stat
#from os.path import basename

class Nsd(object):

    def __init__(self, http=None, client=None):
        self._http = http
        self._client = client
        self._apiName = '/nsd'
        self._apiVersion = '/v1'
        self._apiResource = '/ns_descriptors'
        self._apiBase = '{}{}{}'.format(self._apiName,
                                        self._apiVersion, self._apiResource)
        #self._apiBase='/nsds'

    def list(self, filter=None):
        filter_string = ''
        if filter:
            filter_string = '?{}'.format(filter)
        resp = self._http.get_cmd('{}{}'.format(self._apiBase, filter_string))
        #print yaml.safe_dump(resp)
        if resp:
            return resp
        return list()

    def get(self, name):
        if utils.validate_uuid4(name):
            for nsd in self.list():
                if name == nsd['_id']:
                    return nsd
        else:
            for nsd in self.list():
                if 'name' in nsd and name == nsd['name']:
                    return nsd
        raise NotFound("nsd {} not found".format(name))

    def get_individual(self, name):
        nsd = self.get(name)
        # It is redundant, since the previous one already gets the whole nsdinfo
        # The only difference is that a different primitive is exercised
        resp = self._http.get_cmd('{}/{}'.format(self._apiBase, nsd['_id']))
        #print yaml.safe_dump(resp)
        if resp:
            return resp
        raise NotFound("nsd {} not found".format(name))

    def get_thing(self, name, thing, filename):
        nsd = self.get(name)
        headers = self._client._headers
        headers['Accept'] = 'application/binary'
        http_code, resp = self._http.get2_cmd('{}/{}/{}'.format(self._apiBase, nsd['_id'], thing))
        #print 'HTTP CODE: {}'.format(http_code)
        #print 'RESP: {}'.format(resp)
        if http_code in (200, 201, 202, 204):
            if resp:
                #store in a file
                return resp
        else:
            msg = ""
            if resp:
                try:
                    msg = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to get {} from {} - {}".format(thing, name, msg))

    def get_descriptor(self, name, filename):
        self.get_thing(name, 'nsd', filename)

    def get_package(self, name, filename):
        self.get_thing(name, 'package_content', filename)

    def get_artifact(self, name, artifact, filename):
        self.get_thing(name, 'artifacts/{}'.format(artifact), filename)

    def delete(self, name, force=False):
        nsd = self.get(name)
        querystring = ''
        if force:
            querystring = '?FORCE=True'
        http_code, resp = self._http.delete_cmd('{}/{}{}'.format(self._apiBase,
                                         nsd['_id'], querystring))
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
                    resp = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to delete nsd {} - {}".format(name, msg))

    def create(self, filename, overwrite=None, update_endpoint=None):
        mime_type = magic.from_file(filename, mime=True)
        if mime_type is None:
            raise ClientException(
                     "failed to guess MIME type for file '{}'".format(filename))
        headers= self._client._headers
        if mime_type in ['application/yaml', 'text/plain']:
            headers['Content-Type'] = 'application/yaml'
        elif mime_type in ['application/gzip', 'application/x-gzip']:
            headers['Content-Type'] = 'application/gzip'
            #headers['Content-Type'] = 'application/binary'
            # Next three lines are to be removed in next version
            #headers['Content-Filename'] = basename(filename)
            #file_size = stat(filename).st_size
            #headers['Content-Range'] = 'bytes 0-{}/{}'.format(file_size - 1, file_size)
        else:
            raise ClientException(
                     "Unexpected MIME type for file {}: MIME type {}".format(
                         filename, mime_type)
                  )
        headers["Content-File-MD5"] = utils.md5(filename)
        http_header = ['{}: {}'.format(key,val)
                      for (key,val) in list(headers.items())]
        self._http.set_http_header(http_header)
        if update_endpoint:
            http_code, resp = self._http.put_cmd(endpoint=update_endpoint, filename=filename)
        else:
            ow_string = ''
            if overwrite:
                ow_string = '?{}'.format(overwrite)
            self._apiResource = '/ns_descriptors_content'
            self._apiBase = '{}{}{}'.format(self._apiName,
                                            self._apiVersion, self._apiResource)
            endpoint = '{}{}'.format(self._apiBase,ow_string)
            http_code, resp = self._http.post_cmd(endpoint=endpoint, filename=filename)
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
            msg = "Error {}".format(http_code)
            if resp:
                try:
                    msg = "{} - {}".format(msg, json.loads(resp))
                except ValueError:
                    msg = "{} - {}".format(msg, resp)
            raise ClientException("failed to create/update nsd - {}".format(msg))

    def update(self, name, filename):
        nsd = self.get(name)
        endpoint = '{}/{}/nsd_content'.format(self._apiBase, nsd['_id'])
        self.create(filename=filename, update_endpoint=endpoint)

