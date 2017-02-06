#!/usr/bin/env python
#
# Copyright 2013 Akamai Technologies, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
if sys.version_info[0] >= 3:
     # python3
     from urllib import parse
else:
     # python2.7
     import urlparse as parse

import os
import logging
import re
from pprint import pformat

logging.basicConfig()
log = logging.getLogger(__name__)
log.level = logging.INFO

class MockRequest:
    def __init__(self, data_ascii, data_binary, headers, method, url):
        self.body = self.get_data(data_ascii, data_binary)
        log.info("body: %s", self.body)
        self.headers= headers or {}
        self.method = method
        self.url = url

    def get_data(self, data_ascii, data_binary):
        data = ''
        if data_ascii:
            data = data_ascii
        elif data_binary:
            data = data_binary
        # only hash POST for now
        if data and data.startswith("@"):
            data_file = data.lstrip("@")
            try:
                if not os.path.isfile(data_file):
                    raise Exception('%s is not a file' %(data_file))
                filesize = os.stat(data_file).st_size
                # read the file content, and assign to data
                with open(data_file, "r") as f:
                    data = f.read()
                    if data_ascii:
                        data = ''.join(data.splitlines())
                    return data
            except IOError:
                raise
        return data

    def register_hook(self, ignoredA, ignoredB):
        return

def main():
    config = {
        "access_token": 'akab-q5k4krpwxpa3ol73-tnmsmh5wbzppnsuh',
        "client_token": 'akab-v2lbouodealtjk32-qxw36y646zowewqr',
        "host": 'akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net/',
        "max-body": 131072,
        "secret": 'CVaFP9v014j174z5X2Bm60qaVprzfhcDtL+kzJjYzV8=',
        "signed-header": None
    }
    section = "default"
    method = "GET"
    data_ascii = None
    data_binary = None
    url = 'https://akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net//papi/v0/contracts/'

    headers = {}

    segments = parse.urlsplit(url)
    print segments.netloc
    if segments.netloc + '/' != config['host']:
        log.warn("Requested hostname '%s' will be replaced by config host '%s'", segments.netloc, config['host'])
        url = parse.urlunsplit(segments._replace(netloc = config['host']))

    # update the args with the signature
    log.info("Authorization config: %s", pformat(config))

    auth = EdgeGridAuth(
        access_token=config['access_token'],
        client_secret=config['secret'],
        client_token=config['client_token'],
        headers_to_sign=config['signed-header'],
        max_body=config['max-body']
    )

    r = MockRequest(data_ascii, data_binary, headers, method, url)
    auth(r)
    auth_header = r.headers['Authorization']
    log.info("Authorization header: %s", auth_header)

    curl_args = ([ 'curl', '-X', method, '-H', 'Authorization: ' + auth_header, '-H', 'Expect:' ])


if __name__ == "__main__":
    try:
        from akamai.edgegrid import EdgeGridAuth
        from akamai.edgegrid import EdgeRc
    except ImportError:
        print("""
This tool has been updated to use the Akamai EdgeGrid for Python library
to sign requests. That library will need to be installed before you can
make a request.

Please run this command to install the required library:

pip install edgegrid-python""")
        sys.exit(1)


    sys.exit(main())