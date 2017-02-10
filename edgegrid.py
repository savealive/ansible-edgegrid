#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Romeo Theriault <romeot () hawaii.edu>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# see examples/playbooks/uri.yml

DOCUMENTATION = '''
---
This module is
Same as for uri module + following parameters related to Akamai {Open} API
(Credentials created https://control.akamai.com > Main > Configure > Manage APIs)
        secret: "CVaFP9v014j174z5X2xxxxxxxxxxxxxxxxxxxxxxxxxx" (Alias: client_secret)
        host: "https://akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net" (alias: api_host)
        access_token: "akab-q5k4krpwxpa3ol73-xxxxxxxxxxxxxxxx"
        client_token: "akab-v2lbouodealtjk32-xxxxxxxxxxxxxxxx"

        url: <full URL for request or relative url path which will be joined with "https://" + host + /url/path>

'''

EXAMPLES = '''
     - name: Get properties
       edgegrid:
        url: "/papi/v0/properties/?contractId=ctr_3-TE78Q&groupId=grp_89061"
        return_content: yes
        validate_certs: True
        secret: "CVaFP9v014j174z5X2xxxxxxxxxxxxxxxxxxxxxxxxxx"
        host: "https://akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net"
        access_token: "akab-q5k4krpwxpa3ol73-xxxxxxxxxxxxxxxx"
        client_token: "akab-v2lbouodealtjk32-xxxxxxxxxxxxxxxx"
        connection: local
       register: response
     - debug: var=response.json

     - name: Get property versions
       edgegrid:
        url: "/papi/v0/properties/prp_334241/versions/?contractId=ctr_3-TE78Q&groupId=grp_89061"
        return_content: yes
        validate_certs: True
        secret: "CVaFP9v014j174z5X2xxxxxxxxxxxxxxxxxxxxxxxxxx"
        host: "https://akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net"
        access_token: "akab-q5k4krpwxpa3ol73-xxxxxxxxxxxxxxxx"
        client_token: "akab-v2lbouodealtjk32-xxxxxxxxxxxxxxxx"
        connection: local
       register: response
     - debug: var=response.json

     - name: POST request
       edgegrid:
        url: "/papi/v0/properties/?contractId=ctr_3-TE78Q&groupId=grp_89061"
        return_content: yes
        method: POST
        body: "{{ lookup('file','post.json') }}"
        body_format: json
        secret: "CVaFP9v014j174z5X2xxxxxxxxxxxxxxxxxxxxxxxxxx"
        host: "https://akab-k5ccw5obhul4ujrz-7uxaqutr53o2274g.luna.akamaiapis.net"
        access_token: "akab-q5k4krpwxpa3ol73-xxxxxxxxxxxxxxxx"
        client_token: "akab-v2lbouodealtjk32-xxxxxxxxxxxxxxxx"
        connection: local
        status_code: 201
        timeout: 120
       register: response
     - debug: var=response


'''

import cgi
import datetime
import shutil
import tempfile

try:
    import json
except ImportError:
    import simplejson as json
import pydevd
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pycompat24 import get_exception
import ansible.module_utils.six as six
from ansible.module_utils._text import to_text
from ansible.module_utils.urls import fetch_url, url_argument_spec

import sys
if sys.version_info[0] >= 3:
     # python3
     from urllib import parse
else:
     # python2.7
     import urlparse as parse

import os

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

class MockRequest:
    def __init__(self, body, headers, method, url):
        self.body = body
        self.headers= headers or {}
        self.method = method
        self.url = url

    def register_hook(self, ignoredA, ignoredB):
        return

def gen_auth_headers(access_token, client_secret, client_token, url, method, headers_to_sign={}, max_body=131072, body=None):
    auth = EdgeGridAuth(
        access_token=access_token,
        client_secret=client_secret,
        client_token=client_token,
        headers_to_sign=headers_to_sign,
        max_body=max_body
    )

    r = MockRequest(body, headers_to_sign, method, url)
    auth(r)
    auth_header = r.headers['Authorization']
    return auth_header

def write_file(module, url, dest, content):
    # create a tempfile with some test content
    fd, tmpsrc = tempfile.mkstemp()
    f = open(tmpsrc, 'wb')
    try:
        f.write(content)
    except Exception:
        err = get_exception()
        os.remove(tmpsrc)
        module.fail_json(msg="failed to create temporary content file: %s" % str(err))
    f.close()

    checksum_src   = None
    checksum_dest  = None

    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        os.remove(tmpsrc)
        module.fail_json(msg="Source %s does not exist" % (tmpsrc))
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        module.fail_json( msg="Source %s not readable" % (tmpsrc))
    checksum_src = module.sha1(tmpsrc)

    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s not writable" % (dest))
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s not readable" % (dest))
        checksum_dest = module.sha1(dest)
    else:
        if not os.access(os.path.dirname(dest), os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination dir %s not writable" % (os.path.dirname(dest)))

    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
        except Exception:
            err = get_exception()
            os.remove(tmpsrc)
            module.fail_json(msg="failed to copy %s to %s: %s" % (tmpsrc, dest, str(err)))

    os.remove(tmpsrc)


def url_filename(url):
    fn = os.path.basename(six.moves.urllib.parse.urlsplit(url)[2])
    if fn == '':
        return 'index.html'
    return fn


def absolute_location(url, location):
    """Attempts to create an absolute URL based on initial URL, and
    next URL, specifically in the case of a ``Location`` header.
    """

    if '://' in location:
        return location

    elif location.startswith('/'):
        parts = six.moves.urllib.parse.urlsplit(url)
        base = url.replace(parts[2], '')
        return '%s%s' % (base, location)

    elif not location.startswith('/'):
        base = os.path.dirname(url)
        return '%s/%s' % (base, location)

    else:
        return location


def uri(module, url, dest, body, body_format, method, headers, socket_timeout):
    # is dest is set and is a directory, let's check if we get redirected and
    # set the filename from that url
    redirected = False
    redir_info = {}
    r = {}
    if dest is not None:
        # Stash follow_redirects, in this block we don't want to follow
        # we'll reset back to the supplied value soon
        follow_redirects = module.params['follow_redirects']
        module.params['follow_redirects'] = False
        dest = os.path.expanduser(dest)
        if os.path.isdir(dest):
            # first check if we are redirected to a file download
            _, redir_info = fetch_url(module, url, data=body,
                                      headers=headers,
                                      method=method,
                                      timeout=socket_timeout)
            # if we are redirected, update the url with the location header,
            # and update dest with the new url filename
            if redir_info['status'] in (301, 302, 303, 307):
                url = redir_info['location']
                redirected = True
            dest = os.path.join(dest, url_filename(url))
        # if destination file already exist, only download if file newer
        if os.path.exists(dest):
            t = datetime.datetime.utcfromtimestamp(os.path.getmtime(dest))
            tstamp = t.strftime('%a, %d %b %Y %H:%M:%S +0000')
            headers['If-Modified-Since'] = tstamp

        # Reset follow_redirects back to the stashed value
        module.params['follow_redirects'] = follow_redirects

    resp, info = fetch_url(module, url, data=body, headers=headers,
                           method=method, timeout=socket_timeout)

    try:
        content = resp.read()
    except AttributeError:
        # there was no content, but the error read()
        # may have been stored in the info as 'body'
        content = info.pop('body', '')

    r['redirected'] = redirected or info['url'] != url
    r.update(redir_info)
    r.update(info)

    return r, content, dest


def main():
    argument_spec = url_argument_spec()
    argument_spec.update(dict(
        dest = dict(required=False, default=None, type='path'),
        url_username = dict(required=False, default=None, aliases=['user']),
        url_password = dict(required=False, default=None, aliases=['password']),
        body = dict(required=False, default=None, type='raw'),
        body_format = dict(required=False, default='raw', choices=['raw', 'json']),
        method = dict(required=False, default='GET', choices=['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT', 'REFRESH']),
        return_content = dict(required=False, default='no', type='bool'),
        follow_redirects = dict(required=False, default='safe', choices=['all', 'safe', 'none', 'yes', 'no']),
        creates = dict(required=False, default=None, type='path'),
        removes = dict(required=False, default=None, type='path'),
        status_code = dict(required=False, default=[200], type='list'),
        timeout=dict(required=False, default=30, type='int'),
        api_host=dict(required=False, default=None, aliases=['host']),
        access_token=dict(required=True, default=None),
        client_token=dict(required=False, default=None),
        client_secret=dict(required=False, default=None, aliases=['secret']),
        max_body=dict(required=False, default=131072, type='int', aliases=['max-body']),
        headers=dict(required=False, type='dict', default={})
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        check_invalid_arguments=False,
        add_file_common_args=True
    )
    url = module.params['url']
    api_host = module.params['api_host']
    url  = parse.urljoin(api_host, url, allow_fragments=True)
    body = module.params['body']
    body_format = module.params['body_format'].lower()
    method = module.params['method']
    dest = module.params['dest']
    return_content = module.params['return_content']
    creates = module.params['creates']
    removes = module.params['removes']
    status_code = [int(x) for x in list(module.params['status_code'])]
    socket_timeout = module.params['timeout']
    access_token = module.params['access_token']
    client_token = module.params["client_token"]
    client_secret = module.params["secret"]
    max_body = module.params["max_body"]
    dict_headers = module.params['headers']

    if body_format == 'json':
        # Encode the body unless its a string, then assume it is pre-formatted JSON
        if not isinstance(body, basestring):
            body = json.dumps(body)
        dict_headers['Content-Type'] = 'application/json'

    # Grab all the http headers. Need this hack since passing multi-values is
    # currently a bit ugly. (e.g. headers='{"Content-Type":"application/json"}')
    for key, value in six.iteritems(module.params):
        if key.startswith("HEADER_"):
            skey = key.replace("HEADER_", "")
            dict_headers[skey] = value

    if creates is not None:
        # do not run the command if the line contains creates=filename
        # and the filename already exists.  This allows idempotence
        # of uri executions.
        if os.path.exists(creates):
            module.exit_json(stdout="skipped, since %s exists" % creates,
                             changed=False, stderr=False, rc=0)

    if removes is not None:
        # do not run the command if the line contains removes=filename
        # and the filename do not exists.  This allows idempotence
        # of uri executions.
        if not os.path.exists(removes):
            module.exit_json(stdout="skipped, since %s does not exist" % removes, changed=False, stderr=False, rc=0)


    #Get akamai auth header
    dict_headers['Authorization'] = gen_auth_headers(access_token,
                                                     client_secret,
                                                     client_token,
                                                     url, method, dict_headers, max_body,
                                                     body=body)

    # Make the request
    resp, content, dest = uri(module, url, dest, body, body_format, method,
                              dict_headers, socket_timeout)
    resp['status'] = int(resp['status'])

    # Write the file out if requested
    if dest is not None:
        if resp['status'] == 304:
            changed = False
        else:
            write_file(module, url, dest, content)
            # allow file attribute changes
            changed = True
            module.params['path'] = dest
            file_args = module.load_file_common_arguments(module.params)
            file_args['path'] = dest
            changed = module.set_fs_attributes_if_different(file_args, changed)
        resp['path'] = dest
    else:
        changed = False

    # Transmogrify the headers, replacing '-' with '_', since variables dont
    # work with dashes.
    # In python3, the headers are title cased.  Lowercase them to be
    # compatible with the python2 behaviour.
    uresp = {}
    for key, value in six.iteritems(resp):
        ukey = key.replace("-", "_").lower()
        uresp[ukey] = value

    try:
        uresp['location'] = absolute_location(url, uresp['location'])
    except KeyError:
        pass

    # Default content_encoding to try
    content_encoding = 'utf-8'
    if 'content_type' in uresp:
        content_type, params = cgi.parse_header(uresp['content_type'])
        if 'charset' in params:
            content_encoding = params['charset']
        u_content = to_text(content, encoding=content_encoding)
        if 'application/json' in content_type or 'text/json' in content_type:
            try:
                js = json.loads(u_content)
                uresp['json'] = js
            except:
                pass
    else:
        u_content = to_text(content, encoding=content_encoding)

    if resp['status'] not in status_code:
        uresp['msg'] = 'Status code was not %s: %s' % (status_code, uresp.get('msg', ''))
        module.fail_json(content=u_content, **uresp)
    elif return_content:
        module.exit_json(changed=changed, content=u_content, **uresp)
    else:
        module.exit_json(changed=changed, **uresp)


if __name__ == '__main__':
    main()
