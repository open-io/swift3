# Copyright (c) 2018 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import json

from swift.common.utils import public

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import fromstring, DocumentInvalid, XMLSyntaxError
from swift3.response import HTTPOk, NoSuchBucket, MalformedXML, \
                            NoSuchBucket, NoSuchCORSConfiguration
from swift3.utils import LOGGER, sysmeta_header

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')


def get_cors(app, req, origin):
    # should use memcached ?
    resp = req._get_response(app, 'HEAD',
                             req.container_name, "")
    print("XXXX", resp)
    body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
    if not body:
        print("XXXX no CORS for", req.container_name)
        return None
    print("XXXX", body)
    data = fromstring(body, "CorsConfiguration")

    # we have to iterate over each to find matching origin
    # (if origin is domain.com, does it mean http://domain.com and https://domain.com ?

    print("XXXXX root", data.tag)
    rules = data.findall('CORSRule')
    print("XXXX found", len(rules), "rules")
    for rule in rules:
        item = rule.find('AllowedOrigin')
        print("XXXX testing '%s' vs '%s'" % (item.text, origin))
        # TODO(MB): does '*' should be only tested at end or
        # do we have to respect order (even incorrect) from XML ?
        # TODO(MB): manage if rule is something like http://*.example.com
        if item.text == origin or item.text == '*':
            print("XXXXX found", origin)
            return rule
    else:
        print("XXXXX not found")
    return None

def cors_fill_headers(req, resp, rule):
    def set_header_if_item(hdr, tag):
        x = rule.find(tag)
        print(x)
        if x != None:
            resp.headers[hdr] = x.text
        else:
            print("XXXX %s not found in rule" % tag)

    set_header_if_item('Access-Control-Allow-Origin', 'AllowedOrigin')


class CorsController(Controller):
    """
    Handles the following APIs:

     - GET Bucket CORS
     - PUT Bucket CORS
     - DELETE Bucket CORS

    """
    @public
    @bucket_operation
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket CORS.
        """
        resp = req._get_response(self.app, 'HEAD',
                                 req.container_name, None)
        body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
        if not body:
            raise NoSuchCORSConfiguration
        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket CORs.
        """
        xml = req.xml(MAX_CORS_BODY_SIZE)
        try:
            fromstring(xml, "CorsConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            LOGGER.error(e)
            raise exc_type, exc_value, exc_traceback

        req.headers[BUCKET_CORS_HEADER] = xml
        resp = req._get_response(self.app, 'POST',
                                 req.container_name, None)
        return resp


    @public
    @bucket_operation
    def DELETE(self, req):
        """
        Handles DELETE Bucket CORs.
        """
        req.headers[BUCKET_CORS_HEADER] = ''
        return req._get_response(self.app, 'POST',
                                 req.container_name, None)
